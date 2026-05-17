//! Adapter types for FerrisKey REST responses.
//!
//! Field names mirror FerrisKey's OpenAPI shape (`snake_case`) so JSON
//! decoding is direct. We deliberately use plain `Option<T>` instead of the
//! generated client's `Option<Option<T>>` "double option" pattern — every
//! call site treats absent and explicit-null the same.

use serde::{Deserialize, Serialize};

/// One step in the password / OTP flow returned by `/login-actions/authenticate`,
/// `/challenge-otp`, `/verify-otp`, etc.
///
/// `Success` carries an OIDC `url` containing the `?code=&state=` we then
/// exchange at the token endpoint. The other variants carry a temporary
/// JWT that subsequent step-up calls must present as `Authorization: Bearer`.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticateResponse {
    pub status: AuthenticationStatus,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub required_actions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
pub enum AuthenticationStatus {
    Success,
    RequiresActions,
    RequiresOtpChallenge,
    Failed,
}

/// Subset of the FerrisKey `User` record we actually consume.
#[derive(Debug, Clone, Deserialize)]
pub struct FerrisKeyUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub firstname: String,
    #[serde(default)]
    pub lastname: String,
}

/// FerrisKey wraps list responses in `{ "data": [...] }`.
#[derive(Debug, Clone, Deserialize)]
pub struct UsersResponse {
    pub data: Vec<FerrisKeyUser>,
}

/// FerrisKey wraps single-record responses in `{ "data": <User> }` — used by
/// `POST /users` and `GET /users/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct UserResponse {
    pub data: FerrisKeyUser,
}

/// Successful response from `/protocol/openid-connect/token`.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// One credential listed by `/users/{id}/credentials`. FerrisKey returns
/// `credential_type` as a free-form string (`"password"`, `"webauthn"`, …)
/// and the human label under `user_label`.
#[derive(Debug, Clone, Deserialize)]
pub struct UserCredential {
    pub id: String,
    pub credential_type: String,
    #[serde(default)]
    pub user_label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserCredentialsResponse {
    pub data: Vec<UserCredential>,
}

/// Bundle representing a captured FerrisKey auth-flow session — what we
/// stash in tower-sessions for the duration of one login attempt.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FerrisKeyFlow {
    /// Value of FerrisKey's `FERRISKEY_SESSION` cookie (a UUID).
    pub session_code: String,
    /// `state` we sent on `/auth` — used to verify the redirect when
    /// `Success` lands.
    pub state: String,
    /// Temporary JWT returned mid-flow (`RequiresActions` /
    /// `RequiresOtpChallenge`). Required as Bearer for step-up calls.
    #[serde(default)]
    pub temp_token: Option<String>,
    /// PKCE code verifier — random per-flow secret. We send its SHA-256
    /// challenge on `/auth` and the raw verifier on `/token`. Storing only
    /// the verifier is sufficient (challenge is derivable).
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// OIDC `nonce` — random per-flow secret sent on `/auth` and echoed
    /// back in the id_token's `nonce` claim. Binds the id_token to this
    /// specific auth request, defending against id-token replay.
    #[serde(default)]
    pub nonce: Option<String>,
}

// PasskeyInfo lives in crate::types (ungated) so both web + server can use it.
pub use crate::types::PasskeyInfo;
