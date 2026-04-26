//! Custom login flow handlers using Zitadel Session API v2.
//!
//! Supports Passkey (WebAuthn) and Email OTP authentication methods.
//! OTP codes are generated and sent via our own SMTP (not Zitadel).

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::handlers::shared;
use crate::handlers::shared::{AuthUserInfo, determine_post_login_redirect, lookup_or_create_user};
use crate::session::LoggedInData;
use crate::state::AuthState;
use crate::types::AuthTosAcceptance;
use crate::zitadel;

// ── Session keys for temporary login state ──────────────────────────

const ZITADEL_SESSION_ID_KEY: &str = "zitadel_session.id";
const ZITADEL_SESSION_TOKEN_KEY: &str = "zitadel_session.token";
const LOGIN_EMAIL_KEY: &str = "zitadel_session.email";
const ZITADEL_USER_ID_KEY: &str = "zitadel_session.zitadel_user_id";

// TOS acceptance
pub const TOS_VERSION: &str = "1.0";
pub(crate) const TOS_PENDING_REDIRECT_KEY: &str = "tos.pending_redirect";

// Custom OTP session keys
const CUSTOM_OTP_CODE_KEY: &str = "custom_otp.code";
const CUSTOM_OTP_EXPIRES_AT_KEY: &str = "custom_otp.expires_at";
const CUSTOM_OTP_PURPOSE_KEY: &str = "custom_otp.purpose";
const CUSTOM_OTP_ATTEMPTS_KEY: &str = "custom_otp.attempts";
const MAX_OTP_ATTEMPTS: u32 = 5;

// Deferred user creation: set when a new user starts login but hasn't verified OTP yet.
// The Zitadel user is only created after OTP is verified, preventing bot-created accounts.
const DEFERRED_NEW_USER_KEY: &str = "zitadel_session.deferred_new_user";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_tos_acceptance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyPasskeyRequest {
    pub credential_assertion_data: serde_json::Value,
}

#[derive(Deserialize)]
pub struct VerifyOtpRequest {
    pub code: String,
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
}

// ── Helpers ─────────────────────────────────────────────────────────

fn get_service_token(auth_config: &AuthConfig) -> AuthResult<&str> {
    auth_config
        .zitadel_service_user_token
        .as_deref()
        .ok_or_else(|| {
            AuthError::ServerStateError("ZITADEL_SERVICE_USER_TOKEN not configured".to_string())
        })
}

fn rp_domain(auth_config: &AuthConfig) -> String {
    url::Url::parse(&auth_config.base_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "localhost".to_string())
}

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

    info!(to = %email, purpose = %purpose, "Sent OTP verification code");
    Ok(())
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

// ── POST /auth/session/start ────────────────────────────────────────

pub async fn start_session(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<StartSessionRequest>,
) -> AuthResult<Json<StartSessionResponse>> {
    let domain = &auth_config.zitadel_domain;
    let token = get_service_token(&auth_config)?;
    let org_id = auth_config.zitadel_org_id.as_deref();
    let email = req.email.trim().to_lowercase();

    info!("start_session: org_id={:?}, email={}", org_id, email);

    if !shared::is_valid_email(&email) {
        return Err(AuthError::BadRequest("Invalid email address".to_string()));
    }

    // Store redirect intent for post-login use
    if let Some(ref url) = req.redirect_url
        && shared::is_safe_redirect_url(url)
    {
        session
            .insert(shared::LOGIN_REDIRECT_URL_SESSION_KEY, url)
            .await?;
    }

    let zitadel_user = match zitadel::find_user_by_login_name(domain, token, &email, org_id).await?
    {
        Some(user) => Some(user),
        None => {
            info!(
                "User '{}' not found by login name, trying email lookup",
                email
            );
            zitadel::find_user_by_email(domain, token, &email, org_id).await?
        }
    };

    session.insert(LOGIN_EMAIL_KEY, &email).await?;

    if let Some(user) = zitadel_user {
        // ── Existing user ────────────────────────────────────────────
        let zitadel_user_id = user.user_id;
        session
            .insert(ZITADEL_USER_ID_KEY, &zitadel_user_id)
            .await?;

        let passkeys = zitadel::list_passkeys(domain, token, &zitadel_user_id)
            .await
            .unwrap_or_else(|e| {
                warn!(
                    "Failed to list passkeys for user {}: {:?}",
                    zitadel_user_id, e
                );
                vec![]
            });
        let has_passkeys = !passkeys.is_empty();

        if has_passkeys {
            let rp = rp_domain(&auth_config);
            match zitadel::create_session_with_passkey_challenge(
                domain,
                token,
                &email,
                &rp,
                Some(&zitadel_user_id),
            )
            .await
            {
                Ok(response) => {
                    session
                        .insert(ZITADEL_SESSION_ID_KEY, &response.session_id)
                        .await?;
                    session
                        .insert(ZITADEL_SESSION_TOKEN_KEY, &response.session_token)
                        .await?;

                    let public_key_options = response
                        .challenges
                        .as_ref()
                        .and_then(|c| c.web_auth_n.as_ref())
                        .map(|w| w.public_key_credential_request_options.clone());

                    info!(
                        "Passkey session created: id={}, has_passkeys=true",
                        response.session_id
                    );

                    Ok(Json(StartSessionResponse {
                        session_id: response.session_id,
                        public_key_options,
                        otp_sent: false,
                        is_new_user: false,
                        has_passkeys,
                        needs_tos_acceptance: None,
                        redirect_url: None,
                    }))
                }
                Err(e) => {
                    warn!("Passkey challenge failed, falling back to OTP: {:?}", e);
                    send_otp_session(
                        &auth_state,
                        &auth_config,
                        &session,
                        domain,
                        token,
                        &zitadel_user_id,
                        &email,
                        false,
                        has_passkeys,
                    )
                    .await
                }
            }
        } else {
            send_otp_session(
                &auth_state,
                &auth_config,
                &session,
                domain,
                token,
                &zitadel_user_id,
                &email,
                false,
                false,
            )
            .await
        }
    } else {
        // ── New user: defer Zitadel creation until OTP is verified ──
        info!(
            "User '{}' not found in Zitadel, deferring creation until OTP verified",
            email
        );
        session.insert(DEFERRED_NEW_USER_KEY, true).await?;

        generate_and_send_otp(&auth_state, &session, &email, "login").await?;

        info!("OTP sent to new user (deferred): {}", email);

        Ok(Json(StartSessionResponse {
            session_id: String::new(),
            public_key_options: None,
            otp_sent: true,
            is_new_user: true,
            has_passkeys: false,
            needs_tos_acceptance: None,
            redirect_url: None,
        }))
    }
}

/// Helper: create a Zitadel session with user check only, generate + send OTP.
#[allow(clippy::too_many_arguments)]
async fn send_otp_session(
    auth_state: &AuthState,
    _auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    domain: &str,
    token: &str,
    zitadel_user_id: &str,
    email: &str,
    is_new_user: bool,
    has_passkeys: bool,
) -> AuthResult<Json<StartSessionResponse>> {
    let response = zitadel::create_session_user_check_only(domain, token, zitadel_user_id).await?;

    session
        .insert(ZITADEL_SESSION_ID_KEY, &response.session_id)
        .await?;
    session
        .insert(ZITADEL_SESSION_TOKEN_KEY, &response.session_token)
        .await?;

    generate_and_send_otp(auth_state, session, email, "login").await?;

    info!(
        "OTP session created: zitadel_session_id={}, email={}",
        response.session_id, email
    );

    Ok(Json(StartSessionResponse {
        session_id: response.session_id,
        public_key_options: None,
        otp_sent: true,
        is_new_user,
        has_passkeys,
        needs_tos_acceptance: None,
        redirect_url: None,
    }))
}

// ── POST /auth/session/passkey/verify ───────────────────────────────

pub async fn verify_passkey_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyPasskeyRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let domain = &auth_config.zitadel_domain;
    let token = get_service_token(&auth_config)?;

    let session_id = session
        .get::<String>(ZITADEL_SESSION_ID_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login session in progress".to_string()))?;

    let session_token = session
        .get::<String>(ZITADEL_SESSION_TOKEN_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No session token in progress".to_string()))?;

    match zitadel::verify_passkey(
        domain,
        token,
        &session_id,
        &session_token,
        req.credential_assertion_data,
    )
    .await
    {
        Ok(_update_resp) => {
            let result = finalize_login(&auth_state, &auth_config, &session).await?;
            Ok(Json(VerifyResponse {
                success: true,
                redirect_url: result.redirect_url,
                needs_tos_acceptance: if result.needs_tos_acceptance {
                    Some(true)
                } else {
                    None
                },
                error: None,
            }))
        }
        Err(e) => {
            warn!("Passkey verification failed: {:?}", e);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some("Passkey verification failed. Please try again.".to_string()),
            }))
        }
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
            let domain = &auth_config.zitadel_domain;
            let token = get_service_token(&auth_config)?;
            let is_deferred = session
                .get::<bool>(DEFERRED_NEW_USER_KEY)
                .await?
                .unwrap_or(false);

            if is_deferred {
                // ── Deferred new user: create Zitadel user now ───────
                let org_id = auth_config.zitadel_org_id.as_deref();
                let email = session
                    .get::<String>(LOGIN_EMAIL_KEY)
                    .await?
                    .ok_or_else(|| {
                        AuthError::ServerStateError("Missing login email".to_string())
                    })?;

                let created = zitadel::create_human_user(domain, token, &email, org_id).await?;

                let zitadel_user_id = if created.user_id.is_empty() {
                    // Race: user was created between start and verify
                    zitadel::find_user_by_email(domain, token, &email, org_id)
                        .await?
                        .map(|u| u.user_id)
                        .ok_or_else(|| {
                            AuthError::ServerStateError(
                                "Could not resolve Zitadel user ID".to_string(),
                            )
                        })?
                } else {
                    created.user_id
                };

                // Mark email verified (OTP proved ownership)
                if let Err(e) =
                    zitadel::set_user_email_verified(domain, token, &zitadel_user_id, &email).await
                {
                    warn!("Failed to mark email as verified in Zitadel: {:?}", e);
                }

                // Create Zitadel session (required by finalize_login)
                let response =
                    zitadel::create_session_user_check_only(domain, token, &zitadel_user_id)
                        .await?;
                session
                    .insert(ZITADEL_SESSION_ID_KEY, &response.session_id)
                    .await?;
                session
                    .insert(ZITADEL_SESSION_TOKEN_KEY, &response.session_token)
                    .await?;
                session
                    .insert(ZITADEL_USER_ID_KEY, &zitadel_user_id)
                    .await?;
                session.remove::<bool>(DEFERRED_NEW_USER_KEY).await?;
            } else {
                // ── Existing user: mark email verified (idempotent) ──
                let zitadel_user_id = session.get::<String>(ZITADEL_USER_ID_KEY).await?;
                let email = session.get::<String>(LOGIN_EMAIL_KEY).await?;

                if let (Some(uid), Some(email)) = (&zitadel_user_id, &email)
                    && let Err(e) =
                        zitadel::set_user_email_verified(domain, token, uid, email).await
                {
                    warn!("Failed to mark email as verified in Zitadel: {:?}", e);
                }
            }

            let result = finalize_login(&auth_state, &auth_config, &session).await?;
            Ok(Json(VerifyResponse {
                success: true,
                redirect_url: result.redirect_url,
                needs_tos_acceptance: if result.needs_tos_acceptance {
                    Some(true)
                } else {
                    None
                },
                error: None,
            }))
        }
        Err(msg) => {
            warn!("OTP verification failed: {}", msg);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(msg),
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
    }))
}

// ── POST /auth/session/passkey-fallback-otp ──────────────────────────

/// When the client-side passkey auth fails (cancelled, wrong device, etc.),
/// the client calls this endpoint to fall back to email OTP.
pub async fn passkey_fallback_to_otp(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
) -> AuthResult<Json<StartSessionResponse>> {
    let domain = &auth_config.zitadel_domain;
    let token = get_service_token(&auth_config)?;

    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login session in progress".to_string()))?;

    let zitadel_user_id = session
        .get::<String>(ZITADEL_USER_ID_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No user ID in session".to_string()))?;

    info!("Passkey fallback to OTP for user {}", email);

    // Create a new Zitadel session (the passkey one is no longer usable)
    let response = zitadel::create_session_user_check_only(domain, token, &zitadel_user_id).await?;

    session
        .insert(ZITADEL_SESSION_ID_KEY, &response.session_id)
        .await?;
    session
        .insert(ZITADEL_SESSION_TOKEN_KEY, &response.session_token)
        .await?;

    generate_and_send_otp(&auth_state, &session, &email, "login").await?;

    info!(
        "Passkey fallback: OTP sent to {}, new session_id={}",
        email, response.session_id
    );

    Ok(Json(StartSessionResponse {
        session_id: response.session_id,
        public_key_options: None,
        otp_sent: true,
        is_new_user: false,
        has_passkeys: true,
        needs_tos_acceptance: None,
        redirect_url: None,
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
) -> AuthResult<FinalizeResult> {
    let domain = &auth_config.zitadel_domain;
    let service_token = get_service_token(auth_config)?;

    let session_id = session
        .get::<String>(ZITADEL_SESSION_ID_KEY)
        .await?
        .ok_or_else(|| AuthError::ServerStateError("Missing zitadel session id".to_string()))?;

    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::ServerStateError("Missing login email".to_string()))?;

    let zitadel_session = zitadel::get_session(domain, service_token, &session_id).await?;

    let user_id = zitadel_session
        .session
        .factors
        .as_ref()
        .and_then(|f| f.user.as_ref())
        .and_then(|u| u.id.clone())
        .ok_or_else(|| {
            AuthError::ServerStateError(
                "Zitadel session has no user factor — cannot determine user ID".to_string(),
            )
        })?;

    let display_name = zitadel_session
        .session
        .factors
        .as_ref()
        .and_then(|f| f.user.as_ref())
        .and_then(|u| u.display_name.clone());

    let info = AuthUserInfo {
        sub: user_id,
        name: display_name,
        nickname: None,
        email: email.clone(),
        picture: None,
        preferred_username: Some(email.clone()),
    };

    let user = lookup_or_create_user(auth_state, &info).await?;

    info!("Session API login successful for user {}", user.id);

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
    };
    crate::session::login(session, &data).await?;

    // Clean up temporary session keys
    session.remove::<String>(ZITADEL_SESSION_ID_KEY).await?;
    session.remove::<String>(ZITADEL_SESSION_TOKEN_KEY).await?;
    session.remove::<String>(LOGIN_EMAIL_KEY).await?;
    session.remove::<String>(ZITADEL_USER_ID_KEY).await?;
    session.remove::<String>(CUSTOM_OTP_CODE_KEY).await?;
    session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await?;
    session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await?;
    session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await?;
    session.remove::<bool>(DEFERRED_NEW_USER_KEY).await?;

    // Check TOS acceptance
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
    }))
}
