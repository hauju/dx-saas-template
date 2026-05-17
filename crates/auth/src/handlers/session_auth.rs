//! Custom login flow handlers backed by FerrisKey.
//!
//! Three concrete paths share this state machine:
//!
//! * **Passkey** — `start_session` bootstraps a FerrisKey flow, fetches
//!   `passkey-request-options`, and hands them to the browser. The browser
//!   POSTs the assertion back to `verify_passkey`, which proxies it to
//!   `passkey-authenticate`. On `Success` we exchange the OIDC `code` for
//!   tokens and finalize.
//! * **Password** — `verify_password` calls `/login-actions/authenticate`
//!   with the captured FerrisKey session and the same code-exchange wraps
//!   things up.
//! * **Email OTP** — fully on our side. We mint and email the code, store it
//!   in tower-sessions, and on success either *create* the FerrisKey user
//!   (deferred new-user path, gated by CAPTCHA) or *update* email_verified.
//!   No FerrisKey flow is involved on this path — we look the user up by
//!   email and use that record's `id` as the OIDC subject.

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::ferriskey;
use crate::ferriskey::{
    AuthenticateResponse, AuthenticationStatus, FerrisKeyFlow, FerrisKeyUser, OidcTokenResponse,
};
use crate::handlers::shared;
use crate::handlers::shared::{AuthUserInfo, determine_post_login_redirect, lookup_or_create_user};
use crate::session::LoggedInData;
use crate::state::AuthState;
use crate::types::AuthTosAcceptance;

// ── Session keys for temporary login state ──────────────────────────

const FLOW_KEY: &str = "ferriskey.flow";
const FERRISKEY_USER_ID_KEY: &str = "ferriskey.user_id";
const LOGIN_EMAIL_KEY: &str = "login.email";

// TOS acceptance
pub const TOS_VERSION: &str = "1.0";
pub(crate) const TOS_PENDING_REDIRECT_KEY: &str = "tos.pending_redirect";

// Custom OTP session keys (our own email OTP, not FerrisKey)
const CUSTOM_OTP_CODE_KEY: &str = "custom_otp.code";
const CUSTOM_OTP_EXPIRES_AT_KEY: &str = "custom_otp.expires_at";
const CUSTOM_OTP_PURPOSE_KEY: &str = "custom_otp.purpose";
const CUSTOM_OTP_ATTEMPTS_KEY: &str = "custom_otp.attempts";
const MAX_OTP_ATTEMPTS: u32 = 5;

// OTP resend throttle
const CUSTOM_OTP_LAST_SENT_AT_KEY: &str = "custom_otp.last_sent_at";
const CUSTOM_OTP_RESEND_COUNT_KEY: &str = "custom_otp.resend_count";
const RESEND_COOLDOWN_SECONDS: i64 = 30;
const MAX_RESEND_COUNT: u32 = 5;

// Deferred user creation: set when a new user starts login but hasn't verified OTP yet.
// The FerrisKey user is only created after OTP is verified, preventing bot-created accounts.
const DEFERRED_NEW_USER_KEY: &str = "ferriskey.deferred_new_user";

// CAPTCHA for new user registration
const CAPTCHA_ANSWER_KEY: &str = "captcha.answer";
const CAPTCHA_EXPIRES_AT_KEY: &str = "captcha.expires_at";
const CAPTCHA_ATTEMPTS_KEY: &str = "captcha.attempts";
const MAX_CAPTCHA_ATTEMPTS: u32 = 5;
const CAPTCHA_EXPIRY_SECONDS: i64 = 300;

const PASSWORD_ATTEMPTS_KEY: &str = "password.attempts";
const MAX_PASSWORD_ATTEMPTS: u32 = 5;

// ── Request / Response types ────────────────────────────────────────

#[derive(Deserialize)]
pub struct StartSessionRequest {
    pub email: String,
    #[serde(default)]
    pub redirect_url: Option<String>,
}

#[derive(Serialize)]
pub struct StartSessionResponse {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_options: Option<serde_json::Value>,
    pub otp_sent: bool,
    pub is_new_user: bool,
    pub has_passkeys: bool,
    pub has_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_tos_acceptance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_image: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyPasskeyRequest {
    pub credential_assertion_data: serde_json::Value,
}

#[derive(Deserialize)]
pub struct VerifyOtpRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct VerifyCaptchaRequest {
    pub answer: String,
}

#[derive(Serialize)]
pub struct CaptchaVerifyResponse {
    pub success: bool,
    pub otp_sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct CaptchaRefreshResponse {
    pub captcha_image: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_tos_acceptance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<i64>,
}

#[derive(Deserialize)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

// ── FerrisKey config helpers ─────────────────────────────────────────

struct FkConfig<'a> {
    base: &'a str,
    realm: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    base_url: &'a str,
}

impl<'a> FkConfig<'a> {
    fn from(auth_config: &'a AuthConfig) -> AuthResult<Self> {
        let client_secret = auth_config
            .ferriskey_client_secret
            .as_deref()
            .ok_or_else(|| {
                AuthError::ServerStateError("FERRISKEY_CLIENT_SECRET not configured".to_string())
            })?;
        Ok(FkConfig {
            base: &auth_config.ferriskey_url,
            realm: &auth_config.ferriskey_realm,
            client_id: &auth_config.ferriskey_client_id,
            client_secret,
            base_url: &auth_config.base_url,
        })
    }
}

/// Get a service-account access token (client_credentials grant) for
/// user-management calls.
async fn service_token(fk: &FkConfig<'_>) -> AuthResult<String> {
    let resp =
        ferriskey::service_account_token(fk.base, fk.realm, fk.client_id, fk.client_secret).await?;
    Ok(resp.access_token)
}

// ── OTP / CAPTCHA helpers ───────────────────────────────────────────

async fn generate_and_send_otp(
    auth_state: &AuthState,
    session: &tower_sessions::Session,
    email: &str,
    purpose: &str,
) -> AuthResult<()> {
    let code = crypto::generate_numeric_otp(6)
        .map_err(|e| AuthError::ServerStateError(format!("Failed to generate OTP: {}", e)))?;

    let expires_at = chrono::Utc::now().timestamp() + 600;
    session.insert(CUSTOM_OTP_CODE_KEY, &code).await?;
    session
        .insert(CUSTOM_OTP_EXPIRES_AT_KEY, expires_at)
        .await?;
    session.insert(CUSTOM_OTP_PURPOSE_KEY, purpose).await?;
    session.insert(CUSTOM_OTP_ATTEMPTS_KEY, 0u32).await?;

    auth_state
        .email_sender
        .send_verification_code(email, &code, 10)
        .await
        .map_err(|e| {
            AuthError::ServerStateError(format!("Failed to send verification email: {}", e))
        })?;

    session
        .insert(CUSTOM_OTP_LAST_SENT_AT_KEY, chrono::Utc::now().timestamp())
        .await?;

    let count = session
        .get::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY)
        .await
        .unwrap_or(None)
        .unwrap_or(0);
    session
        .insert(CUSTOM_OTP_RESEND_COUNT_KEY, count + 1)
        .await?;

    info!(to = %email, purpose = %purpose, "Sent OTP verification code");
    Ok(())
}

async fn generate_captcha(session: &tower_sessions::Session) -> AuthResult<String> {
    let captcha = captcha_rs::CaptchaBuilder::new()
        .length(5)
        .width(220)
        .height(60)
        .dark_mode(true)
        .complexity(5)
        .compression(40)
        .build();

    let answer = captcha.text.to_lowercase();
    let image = captcha.to_base64();

    let expires_at = chrono::Utc::now().timestamp() + CAPTCHA_EXPIRY_SECONDS;
    session.insert(CAPTCHA_ANSWER_KEY, &answer).await?;
    session.insert(CAPTCHA_EXPIRES_AT_KEY, expires_at).await?;
    session.insert(CAPTCHA_ATTEMPTS_KEY, 0u32).await?;

    info!("Generated CAPTCHA for new user registration");
    Ok(image)
}

async fn verify_otp_from_session(
    session: &tower_sessions::Session,
    submitted_code: &str,
) -> std::result::Result<(), String> {
    let stored_code = session
        .get::<String>(CUSTOM_OTP_CODE_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    let expires_at = session
        .get::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    if chrono::Utc::now().timestamp() > expires_at {
        let _ = session.remove::<String>(CUSTOM_OTP_CODE_KEY).await;
        let _ = session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await;
        let _ = session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await;
        let _ = session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await;
        return Err("Verification code has expired. Please request a new one.".to_string());
    }

    let attempts = session
        .get::<u32>(CUSTOM_OTP_ATTEMPTS_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .unwrap_or(0);

    if attempts >= MAX_OTP_ATTEMPTS {
        let _ = session.remove::<String>(CUSTOM_OTP_CODE_KEY).await;
        let _ = session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await;
        let _ = session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await;
        let _ = session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await;
        return Err(
            "Too many failed attempts. Please request a new verification code.".to_string(),
        );
    }

    if submitted_code
        .as_bytes()
        .ct_eq(stored_code.as_bytes())
        .unwrap_u8()
        != 1
    {
        let _ = session.insert(CUSTOM_OTP_ATTEMPTS_KEY, attempts + 1).await;
        return Err("Invalid verification code. Please try again.".to_string());
    }

    let _ = session.remove::<String>(CUSTOM_OTP_CODE_KEY).await;
    let _ = session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await;
    let _ = session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await;
    let _ = session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await;

    Ok(())
}

// ── Flow plumbing ────────────────────────────────────────────────────

async fn store_flow(session: &tower_sessions::Session, flow: &FerrisKeyFlow) -> AuthResult<()> {
    session.insert(FLOW_KEY, flow).await?;
    Ok(())
}

async fn load_flow(session: &tower_sessions::Session) -> AuthResult<FerrisKeyFlow> {
    session
        .get::<FerrisKeyFlow>(FLOW_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login flow in progress".to_string()))
}

/// Pull `code` and `state` out of the OIDC redirect URL returned in
/// `AuthenticateResponse.url` on success. Validates `state` against the flow.
fn parse_oidc_redirect(url: &str, expected_state: &str) -> AuthResult<String> {
    let parsed = url::Url::parse(url).map_err(|e| {
        AuthError::ServerStateError(format!("FerrisKey returned invalid redirect URL: {e}"))
    })?;
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }
    let state = state
        .ok_or_else(|| AuthError::ServerStateError("Missing state in redirect URL".to_string()))?;
    if state != expected_state {
        return Err(AuthError::Unauthorized(
            "Login flow state mismatch — please retry".to_string(),
        ));
    }
    code.ok_or_else(|| AuthError::ServerStateError("Missing code in redirect URL".to_string()))
}

/// Exchange the success `url` for tokens and decode the id_token.
async fn exchange_and_resolve(
    fk: &FkConfig<'_>,
    jwks: &crate::jwt::JwksCache,
    flow: &FerrisKeyFlow,
    redirect_url: &str,
) -> AuthResult<AuthUserInfo> {
    let code = parse_oidc_redirect(redirect_url, &flow.state)?;
    let code_verifier = flow.code_verifier.as_deref().ok_or_else(|| {
        AuthError::ServerStateError("Login flow missing PKCE verifier — please retry".to_string())
    })?;
    let tokens: OidcTokenResponse = ferriskey::exchange_code(
        fk.base,
        fk.realm,
        fk.client_id,
        fk.client_secret,
        &code,
        code_verifier,
        fk.base_url,
    )
    .await?;

    // Validate the id_token via JWKS so we can trust `sub`/`email`. If id_token
    // is missing we fall back to looking the user up by email after the fact.
    let id_token = tokens
        .id_token
        .ok_or_else(|| AuthError::ServerStateError("FerrisKey returned no id_token".to_string()))?;
    let claims = jwks.validate_token(&id_token).await.map_err(|e| {
        AuthError::ServerStateError(format!("Failed to validate FerrisKey id_token: {e}"))
    })?;

    // If FerrisKey echoed a `nonce` claim, it MUST equal the per-flow nonce
    // we sent on `/auth` — otherwise the id_token belongs to a different
    // login attempt. We don't *require* the claim to be present: FerrisKey
    // (current versions) doesn't always include it, and the practical
    // code-flow replay surface is already covered by `state` + PKCE +
    // server-side code redemption. When FerrisKey starts emitting nonce,
    // this check kicks in automatically.
    if let (Some(expected_nonce), Some(returned_nonce)) =
        (flow.nonce.as_deref(), claims.nonce.as_deref())
        && returned_nonce
            .as_bytes()
            .ct_eq(expected_nonce.as_bytes())
            .unwrap_u8()
            != 1
    {
        warn!("FerrisKey id_token nonce mismatch — possible token replay");
        return Err(AuthError::Unauthorized(
            "Login flow nonce mismatch — please retry".to_string(),
        ));
    }

    Ok(AuthUserInfo {
        sub: claims.sub,
        nickname: None,
        name: None,
        email: claims.email.unwrap_or_default(),
        picture: None,
        preferred_username: None,
    })
}

// ── POST /auth/session/start ────────────────────────────────────────

pub async fn start_session(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<StartSessionRequest>,
) -> AuthResult<Json<StartSessionResponse>> {
    let fk = FkConfig::from(&auth_config)?;
    let email = req.email.trim().to_lowercase();

    info!("start_session: email={}", email);

    if !shared::is_valid_email(&email) {
        return Err(AuthError::BadRequest("Invalid email address".to_string()));
    }

    if let Some(ref url) = req.redirect_url
        && shared::is_safe_redirect_url(url)
    {
        session
            .insert(shared::LOGIN_REDIRECT_URL_SESSION_KEY, url)
            .await?;
    }

    session.insert(LOGIN_EMAIL_KEY, &email).await?;

    let svc_token = service_token(&fk).await?;
    let user_lookup = ferriskey::find_user_by_email(fk.base, fk.realm, &svc_token, &email).await?;

    if let Some(user) = user_lookup {
        if !user.enabled {
            warn!("Login attempted for disabled FerrisKey user {}", user.id);
            return Err(AuthError::Unauthorized(
                "This account is disabled".to_string(),
            ));
        }

        let credentials = ferriskey::list_user_credentials(fk.base, fk.realm, &svc_token, &user.id)
            .await
            .map_err(|e| {
                warn!("list_user_credentials failed for {}: {:?}", user.id, e);
                AuthError::ServerStateError("Unable to inspect user credentials".to_string())
            })?;
        let has_passkeys = ferriskey::has_passkey(&credentials);
        let has_password = ferriskey::has_password(&credentials);

        session.insert(FERRISKEY_USER_ID_KEY, &user.id).await?;

        let flow = ferriskey::start_auth_flow(fk.base, fk.realm, fk.client_id, fk.base_url).await?;
        store_flow(&session, &flow).await?;

        if has_passkeys {
            match ferriskey::passkey_request_options(fk.base, fk.realm, &flow, &email).await {
                Ok(options) => {
                    info!("Passkey flow ready for user {}", user.id);
                    return Ok(Json(StartSessionResponse {
                        session_id: String::new(),
                        public_key_options: Some(options),
                        otp_sent: false,
                        is_new_user: false,
                        has_passkeys,
                        has_password: false,
                        needs_tos_acceptance: None,
                        redirect_url: None,
                        captcha_required: None,
                        captcha_image: None,
                    }));
                }
                Err(e) => {
                    warn!("passkey_request_options failed: {:?}", e);
                    return Err(AuthError::ServerStateError(
                        "Unable to start passkey authentication".to_string(),
                    ));
                }
            }
        }

        if has_password {
            // No OTP yet — frontend will collect the password and POST it to
            // /auth/session/password/verify, which uses the same FerrisKey flow.
            info!("Password flow ready for user {}", user.id);
            return Ok(Json(StartSessionResponse {
                session_id: String::new(),
                public_key_options: None,
                otp_sent: false,
                is_new_user: false,
                has_passkeys: false,
                has_password: true,
                needs_tos_acceptance: None,
                redirect_url: None,
                captcha_required: None,
                captcha_image: None,
            }));
        }

        if credentials.is_empty() {
            // App-created email-OTP accounts have no FerrisKey credentials yet.
            // Allow OTP only in this narrow case; accounts with any FerrisKey
            // credential must use FerrisKey-backed authentication.
            session.remove::<FerrisKeyFlow>(FLOW_KEY).await?;
            return send_otp_session(&auth_state, &session, &email, false).await;
        }

        warn!(
            "Existing FerrisKey user {} has credentials, but none are supported by this login screen",
            user.id
        );
        Err(AuthError::Unauthorized(
            "This account has no supported login method".to_string(),
        ))
    } else {
        // ── New user: gate registration with a CAPTCHA before sending an OTP ──
        info!(
            "User '{}' not found in FerrisKey, requiring CAPTCHA before OTP",
            email
        );
        session.insert(DEFERRED_NEW_USER_KEY, true).await?;

        let image = generate_captcha(&session).await?;

        Ok(Json(StartSessionResponse {
            session_id: String::new(),
            public_key_options: None,
            otp_sent: false,
            is_new_user: true,
            has_passkeys: false,
            has_password: false,
            needs_tos_acceptance: None,
            redirect_url: None,
            captcha_required: Some(true),
            captcha_image: Some(image),
        }))
    }
}

/// Send an app-managed email OTP for a new user or an existing account with no
/// FerrisKey credentials. Do not call this as fallback for accounts that have
/// any FerrisKey credential; that would bypass the IdP's configured factors.
async fn send_otp_session(
    auth_state: &AuthState,
    session: &tower_sessions::Session,
    email: &str,
    is_new_user: bool,
) -> AuthResult<Json<StartSessionResponse>> {
    generate_and_send_otp(auth_state, session, email, "login").await?;

    info!("OTP session created (no FerrisKey flow): email={}", email);

    Ok(Json(StartSessionResponse {
        session_id: String::new(),
        public_key_options: None,
        otp_sent: true,
        is_new_user,
        has_passkeys: false,
        has_password: false,
        needs_tos_acceptance: None,
        redirect_url: None,
        captcha_required: None,
        captcha_image: None,
    }))
}

// ── POST /auth/session/passkey/verify ───────────────────────────────

pub async fn verify_passkey_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyPasskeyRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let fk = FkConfig::from(&auth_config)?;
    let flow = load_flow(&session).await?;

    match ferriskey::passkey_authenticate(fk.base, fk.realm, &flow, &req.credential_assertion_data)
        .await
    {
        Ok(resp) => handle_oidc_outcome(&auth_state, &auth_config, &session, &flow, resp).await,
        Err(e) => {
            warn!("Passkey verification failed: {:?}", e);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some("Passkey verification failed. Please try again.".to_string()),
                retry_after_seconds: None,
            }))
        }
    }
}

// ── POST /auth/session/password/verify ──────────────────────────────

pub async fn verify_password_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyPasswordRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let fk = FkConfig::from(&auth_config)?;
    let flow = load_flow(&session).await?;

    let attempts = session
        .get::<u32>(PASSWORD_ATTEMPTS_KEY)
        .await?
        .unwrap_or(0);
    if attempts >= MAX_PASSWORD_ATTEMPTS {
        return Ok(Json(VerifyResponse {
            success: false,
            redirect_url: None,
            needs_tos_acceptance: None,
            error: Some("Too many failed password attempts. Please start a new login.".to_string()),
            retry_after_seconds: None,
        }));
    }

    let password = req.password.trim().to_string();
    if password.is_empty() {
        return Err(AuthError::BadRequest("Password is required".to_string()));
    }

    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login session in progress".to_string()))?;

    match ferriskey::authenticate_password(
        fk.base,
        fk.realm,
        fk.client_id,
        &flow,
        &email,
        &password,
    )
    .await
    {
        Ok(resp) => {
            if resp.status == AuthenticationStatus::Failed {
                let _ = session.insert(PASSWORD_ATTEMPTS_KEY, attempts + 1).await;
            } else {
                session.remove::<u32>(PASSWORD_ATTEMPTS_KEY).await?;
            }
            handle_oidc_outcome(&auth_state, &auth_config, &session, &flow, resp).await
        }
        Err(e) => {
            let _ = session.insert(PASSWORD_ATTEMPTS_KEY, attempts + 1).await;
            warn!("Password verification failed: {:?}", e);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some("Invalid password. Please try again.".to_string()),
                retry_after_seconds: None,
            }))
        }
    }
}

/// Branch on `AuthenticateResponse.status` after a password or passkey step.
async fn handle_oidc_outcome(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    flow: &FerrisKeyFlow,
    resp: AuthenticateResponse,
) -> AuthResult<Json<VerifyResponse>> {
    match resp.status {
        AuthenticationStatus::Success => {
            let url = resp.url.ok_or_else(|| {
                AuthError::ServerStateError(
                    "FerrisKey returned Success without a redirect URL".to_string(),
                )
            })?;
            let fk = FkConfig::from(auth_config)?;
            let info = exchange_and_resolve(&fk, &auth_state.jwks_cache, flow, &url).await?;
            let result = finalize_login(auth_state, auth_config, session, &info).await?;
            Ok(Json(VerifyResponse {
                success: true,
                redirect_url: result.redirect_url,
                needs_tos_acceptance: if result.needs_tos_acceptance {
                    Some(true)
                } else {
                    None
                },
                error: None,
                retry_after_seconds: None,
            }))
        }
        AuthenticationStatus::RequiresOtpChallenge | AuthenticationStatus::RequiresActions => {
            // TOTP / required-action step-ups aren't wired into the dashboard
            // UI. Surface a clear message instead of silently failing.
            let label = match resp.status {
                AuthenticationStatus::RequiresOtpChallenge => "TOTP",
                _ => "additional setup",
            };
            warn!(
                "FerrisKey returned {:?} — UI does not yet support {} step-up",
                resp.status, label
            );
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(format!(
                    "Your account requires {label}, which isn't supported by this login screen yet."
                )),
                retry_after_seconds: None,
            }))
        }
        AuthenticationStatus::Failed => Ok(Json(VerifyResponse {
            success: false,
            redirect_url: None,
            needs_tos_acceptance: None,
            error: Some(
                resp.message
                    .unwrap_or_else(|| "Authentication failed".to_string()),
            ),
            retry_after_seconds: None,
        })),
    }
}

// ── POST /auth/session/otp/verify ───────────────────────────────────

pub async fn verify_otp_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyOtpRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let code = req.code.trim().to_string();
    if code.is_empty() {
        return Err(AuthError::BadRequest(
            "Verification code is required".to_string(),
        ));
    }

    match verify_otp_from_session(&session, &code).await {
        Ok(()) => {
            let fk = FkConfig::from(&auth_config)?;
            let svc_token = service_token(&fk).await?;
            let is_deferred = session
                .get::<bool>(DEFERRED_NEW_USER_KEY)
                .await?
                .unwrap_or(false);

            let email = session
                .get::<String>(LOGIN_EMAIL_KEY)
                .await?
                .ok_or_else(|| AuthError::ServerStateError("Missing login email".to_string()))?;

            let user: FerrisKeyUser = if is_deferred {
                let user = ferriskey::create_user(fk.base, fk.realm, &svc_token, &email).await?;
                session.remove::<bool>(DEFERRED_NEW_USER_KEY).await?;
                user
            } else {
                let user = ferriskey::find_user_by_email(fk.base, fk.realm, &svc_token, &email)
                    .await?
                    .ok_or_else(|| {
                        AuthError::ServerStateError(format!(
                            "OTP-verified user '{email}' not found in FerrisKey"
                        ))
                    })?;
                let credentials =
                    ferriskey::list_user_credentials(fk.base, fk.realm, &svc_token, &user.id)
                        .await
                        .map_err(|e| {
                            warn!("list_user_credentials failed for {}: {:?}", user.id, e);
                            AuthError::ServerStateError(
                                "Unable to inspect user credentials".to_string(),
                            )
                        })?;
                if !credentials.is_empty() {
                    return Err(AuthError::Unauthorized(
                        "Email code login is not available for this account".to_string(),
                    ));
                }
                if !user.email_verified {
                    ferriskey::set_email_verified(fk.base, fk.realm, &svc_token, &user.id, &email)
                        .await?;
                }
                user
            };

            if !user.enabled {
                warn!(
                    "OTP login attempted for disabled FerrisKey user {}",
                    user.id
                );
                return Err(AuthError::Unauthorized(
                    "This account is disabled".to_string(),
                ));
            }

            let info = AuthUserInfo {
                sub: user.id.clone(),
                nickname: None,
                name: if user.firstname.is_empty() {
                    None
                } else {
                    Some(user.firstname.clone())
                },
                email: email.clone(),
                picture: None,
                preferred_username: Some(email.clone()),
            };

            let result = finalize_login(&auth_state, &auth_config, &session, &info).await?;
            Ok(Json(VerifyResponse {
                success: true,
                redirect_url: result.redirect_url,
                needs_tos_acceptance: if result.needs_tos_acceptance {
                    Some(true)
                } else {
                    None
                },
                error: None,
                retry_after_seconds: None,
            }))
        }
        Err(msg) => {
            warn!("OTP verification failed: {}", msg);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(msg),
                retry_after_seconds: None,
            }))
        }
    }
}

// ── POST /auth/session/otp/resend ───────────────────────────────────

pub async fn resend_otp_handler(
    Extension(auth_state): Extension<AuthState>,
    session: tower_sessions::Session,
) -> AuthResult<Json<VerifyResponse>> {
    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login session in progress".to_string()))?;

    let resend_count = session
        .get::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY)
        .await?
        .unwrap_or(0);
    if resend_count >= MAX_RESEND_COUNT {
        warn!(email = %email, "OTP resend limit reached ({}/{})", resend_count, MAX_RESEND_COUNT);
        return Ok(Json(VerifyResponse {
            success: false,
            redirect_url: None,
            needs_tos_acceptance: None,
            error: Some("Maximum resend attempts reached. Please start a new login.".to_string()),
            retry_after_seconds: None,
        }));
    }

    if let Some(last_sent_at) = session.get::<i64>(CUSTOM_OTP_LAST_SENT_AT_KEY).await? {
        let elapsed = chrono::Utc::now().timestamp() - last_sent_at;
        if elapsed < RESEND_COOLDOWN_SECONDS {
            let retry_after = RESEND_COOLDOWN_SECONDS - elapsed;
            warn!(email = %email, retry_after, "OTP resend cooldown active");
            return Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(format!(
                    "Please wait {} seconds before requesting a new code.",
                    retry_after
                )),
                retry_after_seconds: Some(retry_after),
            }));
        }
    }

    let purpose = session
        .get::<String>(CUSTOM_OTP_PURPOSE_KEY)
        .await?
        .unwrap_or_else(|| "login".to_string());

    generate_and_send_otp(&auth_state, &session, &email, &purpose).await?;

    Ok(Json(VerifyResponse {
        success: true,
        redirect_url: None,
        needs_tos_acceptance: None,
        error: None,
        retry_after_seconds: Some(RESEND_COOLDOWN_SECONDS),
    }))
}

// ── POST /auth/session/captcha/verify ────────────────────────────────

pub async fn verify_captcha_handler(
    Extension(auth_state): Extension<AuthState>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyCaptchaRequest>,
) -> AuthResult<Json<CaptchaVerifyResponse>> {
    let is_deferred = session
        .get::<bool>(DEFERRED_NEW_USER_KEY)
        .await?
        .unwrap_or(false);
    if !is_deferred {
        return Err(AuthError::BadRequest(
            "No pending registration session".to_string(),
        ));
    }

    let stored_answer = session
        .get::<String>(CAPTCHA_ANSWER_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No CAPTCHA in progress".to_string()))?;

    let expires_at = session
        .get::<i64>(CAPTCHA_EXPIRES_AT_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No CAPTCHA in progress".to_string()))?;

    if chrono::Utc::now().timestamp() > expires_at {
        let _ = session.remove::<String>(CAPTCHA_ANSWER_KEY).await;
        let _ = session.remove::<i64>(CAPTCHA_EXPIRES_AT_KEY).await;
        let _ = session.remove::<u32>(CAPTCHA_ATTEMPTS_KEY).await;
        return Ok(Json(CaptchaVerifyResponse {
            success: false,
            otp_sent: false,
            error: Some("CAPTCHA has expired. Please try again.".to_string()),
        }));
    }

    let attempts = session.get::<u32>(CAPTCHA_ATTEMPTS_KEY).await?.unwrap_or(0);
    if attempts >= MAX_CAPTCHA_ATTEMPTS {
        let _ = session.remove::<String>(CAPTCHA_ANSWER_KEY).await;
        let _ = session.remove::<i64>(CAPTCHA_EXPIRES_AT_KEY).await;
        let _ = session.remove::<u32>(CAPTCHA_ATTEMPTS_KEY).await;
        return Ok(Json(CaptchaVerifyResponse {
            success: false,
            otp_sent: false,
            error: Some("Too many failed attempts. Please try again.".to_string()),
        }));
    }

    let submitted = req.answer.trim().to_lowercase();
    if submitted
        .as_bytes()
        .ct_eq(stored_answer.as_bytes())
        .unwrap_u8()
        != 1
    {
        let _ = session.insert(CAPTCHA_ATTEMPTS_KEY, attempts + 1).await;
        let remaining = MAX_CAPTCHA_ATTEMPTS - attempts - 1;
        return Ok(Json(CaptchaVerifyResponse {
            success: false,
            otp_sent: false,
            error: Some(format!(
                "Incorrect CAPTCHA. {} attempt{} remaining.",
                remaining,
                if remaining == 1 { "" } else { "s" }
            )),
        }));
    }

    let _ = session.remove::<String>(CAPTCHA_ANSWER_KEY).await;
    let _ = session.remove::<i64>(CAPTCHA_EXPIRES_AT_KEY).await;
    let _ = session.remove::<u32>(CAPTCHA_ATTEMPTS_KEY).await;

    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::ServerStateError("Missing login email".to_string()))?;

    generate_and_send_otp(&auth_state, &session, &email, "login").await?;

    info!("CAPTCHA verified, OTP sent to new user: {}", email);

    Ok(Json(CaptchaVerifyResponse {
        success: true,
        otp_sent: true,
        error: None,
    }))
}

// ── POST /auth/session/captcha/refresh ──────────────────────────────

pub async fn refresh_captcha_handler(
    session: tower_sessions::Session,
) -> AuthResult<Json<CaptchaRefreshResponse>> {
    let is_deferred = session
        .get::<bool>(DEFERRED_NEW_USER_KEY)
        .await?
        .unwrap_or(false);
    if !is_deferred {
        return Err(AuthError::BadRequest(
            "No pending registration session".to_string(),
        ));
    }

    let image = generate_captcha(&session).await?;

    Ok(Json(CaptchaRefreshResponse {
        captcha_image: image,
    }))
}

// ── Finalize login ──────────────────────────────────────────────────

struct FinalizeResult {
    redirect_url: Option<String>,
    needs_tos_acceptance: bool,
}

async fn finalize_login(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    info: &AuthUserInfo,
) -> AuthResult<FinalizeResult> {
    let user = lookup_or_create_user(auth_state, info).await?;

    info!("FerrisKey login successful for user {}", user.id);

    let username = user
        .display_name
        .as_ref()
        .filter(|n| !n.is_empty())
        .cloned()
        .unwrap_or_else(|| info.email.split('@').next().unwrap_or("user").to_string());

    session.cycle_id().await?;

    let data = LoggedInData {
        id: user.id.to_string(),
        sub: user.sub.clone(),
        email: user.email.clone(),
        username,
        avatar_url: None,
        id_token: "ferriskey_login".to_string(),
    };
    crate::session::login(session, &data).await?;

    if let Err(e) = auth_state.user_store.record_login(&data.id).await {
        tracing::warn!(user_id = %data.id, "Failed to record last_login_at: {e:?}");
    }

    // Clean up temporary session keys
    session.remove::<FerrisKeyFlow>(FLOW_KEY).await?;
    session.remove::<String>(LOGIN_EMAIL_KEY).await?;
    session.remove::<String>(FERRISKEY_USER_ID_KEY).await?;
    session.remove::<String>(CUSTOM_OTP_CODE_KEY).await?;
    session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await?;
    session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await?;
    session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await?;
    session.remove::<i64>(CUSTOM_OTP_LAST_SENT_AT_KEY).await?;
    session.remove::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY).await?;
    session.remove::<bool>(DEFERRED_NEW_USER_KEY).await?;
    session.remove::<String>(CAPTCHA_ANSWER_KEY).await?;
    session.remove::<i64>(CAPTCHA_EXPIRES_AT_KEY).await?;
    session.remove::<u32>(CAPTCHA_ATTEMPTS_KEY).await?;
    session.remove::<u32>(PASSWORD_ATTEMPTS_KEY).await?;

    let needs_tos = match &user.tos_acceptance {
        Some(ta) => ta.latest_version != TOS_VERSION || !ta.accepted,
        None => true,
    };

    if needs_tos {
        let redirect_url =
            determine_post_login_redirect(auth_state, auth_config, session, &user).await?;
        session
            .insert(TOS_PENDING_REDIRECT_KEY, &redirect_url)
            .await?;
        Ok(FinalizeResult {
            redirect_url: None,
            needs_tos_acceptance: true,
        })
    } else {
        let redirect_url =
            determine_post_login_redirect(auth_state, auth_config, session, &user).await?;
        Ok(FinalizeResult {
            redirect_url: Some(redirect_url),
            needs_tos_acceptance: false,
        })
    }
}

// ── POST /auth/session/accept-tos ───────────────────────────────────

pub async fn accept_tos_handler(
    Extension(auth_state): Extension<AuthState>,
    user_session: crate::session::UserSession,
    session: tower_sessions::Session,
) -> AuthResult<Json<VerifyResponse>> {
    let user_data = user_session.data()?;

    auth_state
        .user_store
        .update_tos_acceptance(
            &user_data.id,
            AuthTosAcceptance {
                latest_version: TOS_VERSION.to_string(),
                accepted: true,
            },
        )
        .await
        .map_err(|e| {
            warn!("Failed to update TOS acceptance: {:?}", e);
            AuthError::ServerStateError("Failed to save TOS acceptance".to_string())
        })?;

    let redirect_url = session
        .remove::<String>(TOS_PENDING_REDIRECT_KEY)
        .await?
        .unwrap_or_else(|| "/dashboard".to_string());

    info!(
        "TOS v{} accepted by user {}, redirecting to {}",
        TOS_VERSION, user_data.id, redirect_url
    );

    Ok(Json(VerifyResponse {
        success: true,
        redirect_url: Some(redirect_url),
        needs_tos_acceptance: None,
        error: None,
        retry_after_seconds: None,
    }))
}
