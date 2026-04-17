//! Adapter types for Zitadel gRPC responses.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub session_token: String,
    #[serde(default)]
    pub challenges: Option<SessionChallengesResponse>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionChallengesResponse {
    #[serde(default)]
    pub web_auth_n: Option<WebAuthNChallengeResponse>,
    #[serde(default)]
    pub otp_email: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthNChallengeResponse {
    pub public_key_credential_request_options: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSessionResponse {
    pub session_token: String,
    #[serde(default)]
    pub challenges: Option<SessionChallengesResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionResponse {
    pub session: SessionInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    #[serde(default)]
    pub factors: Option<SessionFactors>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionFactors {
    #[serde(default)]
    pub user: Option<SessionUserFactor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionUserFactor {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub login_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZitadelUser {
    pub user_id: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub human: Option<ZitadelHumanUser>,
}

#[derive(Debug, Deserialize)]
pub struct ZitadelHumanUser {
    #[serde(default)]
    pub profile: Option<ZitadelProfile>,
    #[serde(default)]
    pub email: Option<ZitadelEmail>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZitadelProfile {
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZitadelEmail {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub is_verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateHumanUserResponse {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationResponse {
    pub passkey_id: String,
    pub public_key_credential_creation_options: serde_json::Value,
}

// PasskeyInfo lives in crate::types (ungated) so both web + server can use it.
pub use crate::types::PasskeyInfo;
