//! API key types.
//!
//! `oat_` API keys authenticate machine-to-machine callers (CLI, integrations,
//! and the MCP connector). The plaintext token is shown to the user exactly once
//! at creation; only its Argon2 hash and an indexed lookup prefix are stored.

use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
use bson::oid::ObjectId;

/// Non-secret metadata about an API key, safe to send to the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    /// Human-friendly label, e.g. "CLI" or "Claude (MCP)".
    pub name: String,
    /// First 12 characters of the token (`oat_` + 8), shown so users can match
    /// a listed key to the value they saved.
    pub prefix: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Returned once, immediately after creation. Carries the plaintext `token`,
/// which is never recoverable afterwards.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewApiKey {
    pub token: String,
    pub info: ApiKeyInfo,
}

/// API key as stored in MongoDB (`api_keys` collection).
#[cfg(feature = "server")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntity {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    /// Owning user (`UserEntity._id`).
    pub user_id: ObjectId,

    /// Human-friendly label.
    pub name: String,

    /// Indexed, non-secret lookup prefix (`crypto::api_key_prefix`).
    pub prefix: String,

    /// Argon2 PHC hash of the full token.
    pub hash: String,

    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(feature = "server")]
impl From<ApiKeyEntity> for ApiKeyInfo {
    fn from(e: ApiKeyEntity) -> Self {
        Self {
            id: e.id.to_hex(),
            name: e.name,
            prefix: e.prefix,
            created_at: e.created_at.to_rfc3339(),
            last_used_at: e.last_used_at.map(|d| d.to_rfc3339()),
        }
    }
}
