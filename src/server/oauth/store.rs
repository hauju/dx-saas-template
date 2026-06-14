//! Persistence for the OAuth authorization server: registered clients and
//! single-use authorization codes.

use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::AppError;
use crate::server::db::Database;

/// A dynamically-registered OAuth client (RFC 7591).
///
/// `client_id` is public, not a secret — the security boundary is the
/// registered `redirect_uris` allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientEntity {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A short-lived, single-use authorization code bound to a PKCE challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCodeEntity {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub user_id: ObjectId,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn insert_client(db: &Database, entity: &OAuthClientEntity) -> Result<(), AppError> {
    db.oauth_clients.insert_one(entity).await?;
    Ok(())
}

pub async fn find_client(
    db: &Database,
    client_id: &str,
) -> Result<Option<OAuthClientEntity>, AppError> {
    Ok(db
        .oauth_clients
        .find_one(bson::doc! { "client_id": client_id })
        .await?)
}

pub async fn insert_code(db: &Database, entity: &OAuthCodeEntity) -> Result<(), AppError> {
    db.oauth_codes.insert_one(entity).await?;
    Ok(())
}

/// Atomically consume an authorization code (find-and-delete), enforcing
/// single use even under concurrent token requests.
pub async fn take_code(db: &Database, code: &str) -> Result<Option<OAuthCodeEntity>, AppError> {
    Ok(db
        .oauth_codes
        .find_one_and_delete(bson::doc! { "code": code })
        .await?)
}
