//! FerrisKey REST client functions.
//!
//! All endpoints are realm-scoped under `{base}/realms/{realm}/...`. The
//! login-actions flow is driven by an opaque server-side session whose code
//! lives in the `FERRISKEY_SESSION` cookie that FerrisKey itself sets via
//! `/protocol/openid-connect/auth`. Most calls in this module take a
//! `session_code` directly and forward it as `Cookie:` themselves so callers
//! can stay uninvolved with cookie plumbing.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::{AuthError, AuthResult};
use crate::ferriskey::types::*;

const SESSION_COOKIE: &str = "FERRISKEY_SESSION";
const STATE_PARAM: &str = "state";
const REDIRECT_URI_PLACEHOLDER: &str = "/auth/callback";

// ── Helpers ──────────────────────────────────────────────────────────

fn http() -> Client {
    // reqwest::Client is internally Arc-wrapped; cheap to construct per call.
    // Sharing a process-wide instance would let connection pools live longer
    // — worth doing later, but not while the surface is still moving.
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest::Client builder should not fail with default config")
}

fn realm_url(base: &str, realm: &str, path: &str) -> String {
    format!(
        "{base}/realms/{realm}{path}",
        base = base.trim_end_matches('/')
    )
}

/// Decode a successful (2xx) JSON response or convert a non-2xx into a typed
/// `FerrisKeyError`. Use this instead of `.error_for_status()?.json()` because
/// we want the response body in the error for tracing.
async fn json_or_error<T>(resp: reqwest::Response, ctx: &str) -> AuthResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let status = resp.status();
    if status.is_success() {
        resp.json::<T>().await.map_err(AuthError::ReqwestError)
    } else {
        let body = resp.text().await.unwrap_or_default();
        warn!("{} failed: {} — {}", ctx, status, body);
        Err(AuthError::FerrisKeyError { status, body })
    }
}

async fn empty_or_error(resp: reqwest::Response, ctx: &str) -> AuthResult<()> {
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        warn!("{} failed: {} — {}", ctx, status, body);
        Err(AuthError::FerrisKeyError { status, body })
    }
}

/// Pull the `FERRISKEY_SESSION` cookie value out of a `Set-Cookie` header
/// list (FerrisKey returns more than one when it also clears the identity
/// cookie). Returns the cookie's *value* (the session UUID), not the full
/// cookie string.
fn extract_session_cookie(resp: &reqwest::Response) -> Option<String> {
    for header in resp.headers().get_all(reqwest::header::SET_COOKIE).iter() {
        let raw = header.to_str().ok()?;
        for piece in raw.split(';') {
            let piece = piece.trim();
            if let Some(value) = piece.strip_prefix(&format!("{SESSION_COOKIE}="))
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
        }
    }
    None
}

// ── Auth flow ────────────────────────────────────────────────────────

/// Bootstrap a FerrisKey auth-flow session.
///
/// Calls `GET /realms/{realm}/protocol/openid-connect/auth` with OIDC params
/// and captures the `FERRISKEY_SESSION` cookie that FerrisKey sets in its
/// 302 response. We discard the `Location:` header — it points at FerrisKey's
/// own login UI which we are replacing.
///
/// Returns a flow struct ready to be parked in the session and threaded into
/// every step-up call.
pub async fn start_auth_flow(
    base: &str,
    realm: &str,
    client_id: &str,
    base_url: &str,
) -> AuthResult<FerrisKeyFlow> {
    let state = generate_state();
    let nonce = generate_nonce();
    let code_verifier = generate_pkce_verifier();
    let code_challenge = pkce_challenge(&code_verifier);
    let redirect_uri = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        REDIRECT_URI_PLACEHOLDER
    );

    let url = realm_url(base, realm, "/protocol/openid-connect/auth");
    let resp = http()
        .get(&url)
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", "openid email profile"),
            (STATE_PARAM, state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await?;

    let status = resp.status();
    if !status.is_redirection() && !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AuthError::FerrisKeyError { status, body });
    }

    let session_code = match extract_session_cookie(&resp) {
        Some(c) => c,
        None => {
            // FerrisKey 302s to a login error page (with `?login_error=…`) when
            // it rejects the request — typically `InvalidRedirectUri`,
            // `ClientNotFound`, or `InvalidRealm` from `CoreError`. Surface
            // the Location header so the operator can see which one.
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<no Location header>");
            return Err(AuthError::ServerStateError(format!(
                "FerrisKey /auth rejected the request (status={status}); Location={location}. \
                Check that client_id={client_id:?}, realm={realm:?}, and redirect_uri are all \
                registered in the FerrisKey console."
            )));
        }
    };

    info!("Started FerrisKey flow");

    Ok(FerrisKeyFlow {
        session_code,
        state,
        temp_token: None,
        code_verifier: Some(code_verifier),
        nonce: Some(nonce),
    })
}

/// Submit username + password to the realm's `login-actions/authenticate`
/// endpoint within an existing flow. Returns the response status enum so the
/// caller can branch on Success / RequiresOtpChallenge / etc.
pub async fn authenticate_password(
    base: &str,
    realm: &str,
    client_id: &str,
    flow: &FerrisKeyFlow,
    username: &str,
    password: &str,
) -> AuthResult<AuthenticateResponse> {
    let url = realm_url(base, realm, "/login-actions/authenticate");
    let resp = http()
        .post(&url)
        .query(&[("client_id", client_id)])
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE}={}", flow.session_code),
        )
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await?;

    json_or_error(resp, "authenticate_password").await
}

/// Submit a TOTP code as a step-up after `RequiresOtpChallenge`. The temp
/// token from the previous step is required as Bearer.
pub async fn challenge_otp(
    base: &str,
    realm: &str,
    flow: &FerrisKeyFlow,
    code: &str,
) -> AuthResult<AuthenticateResponse> {
    let token = flow.temp_token.as_deref().ok_or_else(|| {
        AuthError::ServerStateError("challenge_otp called without a temp_token".to_string())
    })?;

    let url = realm_url(base, realm, "/login-actions/challenge-otp");
    let resp = http()
        .post(&url)
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE}={}", flow.session_code),
        )
        .bearer_auth(token)
        .json(&json!({ "code": code }))
        .send()
        .await?;

    json_or_error(resp, "challenge_otp").await
}

/// Fetch WebAuthn request options for a passkey login attempt. Public
/// endpoint — no Bearer needed. Returns the raw JSON to forward to
/// `navigator.credentials.get({ publicKey })` in the browser.
pub async fn passkey_request_options(
    base: &str,
    realm: &str,
    flow: &FerrisKeyFlow,
    email: &str,
) -> AuthResult<Value> {
    let url = realm_url(base, realm, "/login-actions/passkey-request-options");
    let resp = http()
        .post(&url)
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE}={}", flow.session_code),
        )
        .json(&json!({ "username": email }))
        .send()
        .await?;

    json_or_error(resp, "passkey_request_options").await
}

/// Submit a WebAuthn assertion against `passkey-authenticate`. Public.
pub async fn passkey_authenticate(
    base: &str,
    realm: &str,
    flow: &FerrisKeyFlow,
    assertion: &Value,
) -> AuthResult<AuthenticateResponse> {
    let url = realm_url(base, realm, "/login-actions/passkey-authenticate");
    let resp = http()
        .post(&url)
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE}={}", flow.session_code),
        )
        .json(assertion)
        .send()
        .await?;

    json_or_error(resp, "passkey_authenticate").await
}

// ── Token endpoint ───────────────────────────────────────────────────

/// Exchange a Successful authorization code for an OIDC token bundle.
///
/// `code_verifier` is the PKCE secret originally minted in `start_auth_flow`
/// — FerrisKey re-derives the SHA-256 challenge and rejects mismatches. We
/// keep it required (rather than `Option`) so a caller dropping the verifier
/// turns into a compile error, not a silent downgrade to plain auth-code.
pub async fn exchange_code(
    base: &str,
    realm: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    code_verifier: &str,
    base_url: &str,
) -> AuthResult<OidcTokenResponse> {
    let redirect_uri = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        REDIRECT_URI_PLACEHOLDER
    );
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", code_verifier),
    ];
    let url = realm_url(base, realm, "/protocol/openid-connect/token");
    let resp = http().post(&url).form(&form).send().await?;
    json_or_error(resp, "exchange_code").await
}

/// Run a `client_credentials` grant to get a service-account access token
/// for user-management calls.
pub async fn service_account_token(
    base: &str,
    realm: &str,
    client_id: &str,
    client_secret: &str,
) -> AuthResult<OidcTokenResponse> {
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    let url = realm_url(base, realm, "/protocol/openid-connect/token");
    let resp = http().post(&url).form(&form).send().await?;
    json_or_error(resp, "service_account_token").await
}

// ── User-management API (Bearer = service-account access_token) ─────

/// List users in the realm, then filter client-side by email.
///
/// FerrisKey's current REST surface has no email filter parameter. For the
/// dashboard's expected user count this is fine; if it becomes hot we can
/// add a cache or push for a server-side filter.
pub async fn find_user_by_email(
    base: &str,
    realm: &str,
    service_token: &str,
    email: &str,
) -> AuthResult<Option<FerrisKeyUser>> {
    let url = realm_url(base, realm, "/users");
    let resp = http().get(&url).bearer_auth(service_token).send().await?;
    let users: UsersResponse = json_or_error(resp, "find_user_by_email").await?;

    let needle = email.to_lowercase();
    Ok(users
        .data
        .into_iter()
        .find(|u| u.email.to_lowercase() == needle))
}

/// Create a user with the given email. `firstname` / `lastname` are required
/// strings on FerrisKey's side — we synthesise sensible placeholders that
/// the user can later edit in their profile.
///
/// Callers must only invoke this *after* email ownership has been proven
/// (e.g. successful OTP) — we mark the user verified up front rather than
/// creating unverified and patching, which avoided a silent-failure surface
/// where the follow-up update could fail without anyone noticing.
pub async fn create_user(
    base: &str,
    realm: &str,
    service_token: &str,
    email: &str,
) -> AuthResult<FerrisKeyUser> {
    info!("Creating FerrisKey user for '{}'", email);

    let local_part = email.split('@').next().unwrap_or("user");
    #[derive(Serialize)]
    struct Body<'a> {
        email: &'a str,
        username: &'a str,
        firstname: &'a str,
        lastname: &'a str,
        email_verified: bool,
    }

    let url = realm_url(base, realm, "/users");
    let resp = http()
        .post(&url)
        .bearer_auth(service_token)
        .json(&Body {
            email,
            username: email,
            firstname: local_part,
            lastname: "-",
            email_verified: true,
        })
        .send()
        .await?;

    if resp.status() == StatusCode::CONFLICT {
        info!("FerrisKey user '{}' already exists, looking it up", email);
        return find_user_by_email(base, realm, service_token, email)
            .await?
            .ok_or_else(|| {
                AuthError::ServerStateError(format!(
                    "Race: user {email} reported existing but lookup returned none"
                ))
            });
    }

    let body: UserResponse = json_or_error(resp, "create_user").await?;
    Ok(body.data)
}

/// Mark a user's email as verified after a successful OTP / passkey check.
pub async fn set_email_verified(
    base: &str,
    realm: &str,
    service_token: &str,
    user_id: &str,
    email: &str,
) -> AuthResult<()> {
    let url = realm_url(base, realm, &format!("/users/{user_id}"));
    let resp = http()
        .put(&url)
        .bearer_auth(service_token)
        .json(&json!({ "email": email, "email_verified": true }))
        .send()
        .await?;
    empty_or_error(resp, "set_email_verified").await
}

/// Update a user's display name. FerrisKey splits this across `firstname` /
/// `lastname` — we store the whole display name in `firstname` to round-trip
/// cleanly on subsequent reads.
pub async fn update_display_name(
    base: &str,
    realm: &str,
    service_token: &str,
    user_id: &str,
    display_name: &str,
) -> AuthResult<()> {
    let url = realm_url(base, realm, &format!("/users/{user_id}"));
    let resp = http()
        .put(&url)
        .bearer_auth(service_token)
        .json(&json!({ "firstname": display_name, "lastname": "-" }))
        .send()
        .await?;
    empty_or_error(resp, "update_display_name").await
}

/// List a user's credentials, classified by `credential_type`.
pub async fn list_user_credentials(
    base: &str,
    realm: &str,
    service_token: &str,
    user_id: &str,
) -> AuthResult<Vec<UserCredential>> {
    let url = realm_url(base, realm, &format!("/users/{user_id}/credentials"));
    let resp = http().get(&url).bearer_auth(service_token).send().await?;
    let body: UserCredentialsResponse = json_or_error(resp, "list_user_credentials").await?;
    Ok(body.data)
}

/// True if any of the user's credentials looks like a passkey (FerrisKey
/// labels them `"webauthn"` and/or `"passkey"`).
pub fn has_passkey(credentials: &[UserCredential]) -> bool {
    credentials.iter().any(|c| {
        let t = c.credential_type.to_lowercase();
        t == "webauthn" || t == "passkey"
    })
}

/// True if the user has a password credential set.
pub fn has_password(credentials: &[UserCredential]) -> bool {
    credentials
        .iter()
        .any(|c| c.credential_type.eq_ignore_ascii_case("password"))
}

/// Filter the credential list down to passkey entries, projected to the
/// shape the profile page expects.
pub fn passkeys(credentials: Vec<UserCredential>) -> Vec<PasskeyInfo> {
    credentials
        .into_iter()
        .filter(|c| {
            let t = c.credential_type.to_lowercase();
            t == "webauthn" || t == "passkey"
        })
        .map(|c| PasskeyInfo {
            id: c.id,
            name: c.user_label.unwrap_or_default(),
        })
        .collect()
}

/// Delete a credential by id (used for "remove passkey" on the profile page).
pub async fn delete_user_credential(
    base: &str,
    realm: &str,
    service_token: &str,
    user_id: &str,
    credential_id: &str,
) -> AuthResult<()> {
    let url = realm_url(
        base,
        realm,
        &format!("/users/{user_id}/credentials/{credential_id}"),
    );
    let resp = http()
        .delete(&url)
        .bearer_auth(service_token)
        .send()
        .await?;
    empty_or_error(resp, "delete_user_credential").await
}

// ── Passkey registration (login-actions, Bearer = temp_token) ───────

/// Fetch WebAuthn creation options for registering a new passkey on the
/// currently-authenticated flow. `temp_token` must be the JWT from a prior
/// authenticate step.
pub async fn passkey_create_options(
    base: &str,
    realm: &str,
    flow: &FerrisKeyFlow,
) -> AuthResult<Value> {
    let token = flow.temp_token.as_deref().ok_or_else(|| {
        AuthError::ServerStateError(
            "passkey_create_options called without a temp_token".to_string(),
        )
    })?;
    let url = realm_url(
        base,
        realm,
        "/login-actions/webauthn-public-key-create-options",
    );
    let resp = http()
        .post(&url)
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE}={}", flow.session_code),
        )
        .bearer_auth(token)
        .send()
        .await?;
    json_or_error(resp, "passkey_create_options").await
}

/// Submit a WebAuthn attestation to finish passkey registration.
pub async fn passkey_create(
    base: &str,
    realm: &str,
    flow: &FerrisKeyFlow,
    attestation: &Value,
) -> AuthResult<()> {
    let token = flow.temp_token.as_deref().ok_or_else(|| {
        AuthError::ServerStateError("passkey_create called without a temp_token".to_string())
    })?;
    let url = realm_url(base, realm, "/login-actions/webauthn-public-key-create");
    let resp = http()
        .post(&url)
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE}={}", flow.session_code),
        )
        .bearer_auth(token)
        .json(attestation)
        .send()
        .await?;
    empty_or_error(resp, "passkey_create").await
}

// ── State / PKCE generation ──────────────────────────────────────────

fn generate_state() -> String {
    // OIDC `state` is opaque; 16 url-safe chars is plenty for CSRF binding.
    crypto::generate_url_safe_token(16).expect("secure random generation failed")
}

/// OIDC `nonce` is opaque; 32 url-safe chars (~192 bits) is well past the
/// recommended floor and binds the issued id_token to this specific request.
fn generate_nonce() -> String {
    crypto::generate_url_safe_token(32).expect("secure random generation failed")
}

/// RFC 7636 §4.1: 43–128 chars from `[A-Za-z0-9-._~]`. `generate_url_safe_token`
/// emits a base64url-no-pad string from N random bytes — 64 bytes → 86 chars,
/// well inside the legal range with ~512 bits of entropy.
fn generate_pkce_verifier() -> String {
    crypto::generate_url_safe_token(64).expect("secure random generation failed")
}

/// RFC 7636 §4.2: `code_challenge = base64url-no-pad(sha256(verifier))`.
fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}
