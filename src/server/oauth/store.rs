//! Persistence for the OAuth authorization server: registered clients and
//! single-use authorization codes.
//!
//! Queries use the `query_as!` / `query!` macros, so column names and types are
//! checked against the schema at compile time.
//!
//! Timestamps are assigned by PostgreSQL (`DEFAULT NOW()` on insert, and
//! `make_interval` for code expiry) rather than bound from Rust. That keeps the
//! database clock authoritative — replicas with skewed clocks can't disagree
//! about when a code expires — and sidesteps a binding wrinkle: the session
//! store forces sqlx's `time` feature on, and because Cargo unifies features
//! the macros would otherwise want `time::OffsetDateTime` for every
//! `TIMESTAMPTZ` parameter. Reads use `as "col: Ts"` to pin the same columns
//! back to chrono.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::AppError;
use crate::server::db::Database;

/// Timestamp type for `TIMESTAMPTZ` columns — see the module docs.
type Ts = DateTime<Utc>;

/// A dynamically-registered OAuth client (RFC 7591).
///
/// `client_id` is public, not a secret — the security boundary is the
/// registered `redirect_uris` allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientEntity {
    pub id: Uuid,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A short-lived, single-use authorization code bound to a PKCE challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCodeEntity {
    pub id: Uuid,
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub user_id: Uuid,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
}

/// Register a client. `created_at` is assigned by the database and returned.
pub async fn insert_client(
    db: &Database,
    id: Uuid,
    client_id: &str,
    redirect_uris: &[String],
    client_name: Option<&str>,
) -> Result<OAuthClientEntity, AppError> {
    let created_at = sqlx::query_scalar!(
        r#"INSERT INTO oauth_clients (id, client_id, redirect_uris, client_name)
           VALUES ($1, $2, $3, $4)
           RETURNING created_at as "created_at: Ts""#,
        id,
        client_id,
        redirect_uris,
        client_name,
    )
    .fetch_one(&db.pool)
    .await?;

    Ok(OAuthClientEntity {
        id,
        client_id: client_id.to_string(),
        redirect_uris: redirect_uris.to_vec(),
        client_name: client_name.map(str::to_string),
        created_at,
    })
}

pub async fn find_client(
    db: &Database,
    client_id: &str,
) -> Result<Option<OAuthClientEntity>, AppError> {
    let row = sqlx::query_as!(
        OAuthClientEntity,
        r#"SELECT id, client_id, redirect_uris, client_name,
                  created_at as "created_at: Ts"
           FROM oauth_clients WHERE client_id = $1"#,
        client_id
    )
    .fetch_optional(&db.pool)
    .await?;
    Ok(row)
}

/// Mint an authorization code valid for `ttl_seconds`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_code(
    db: &Database,
    id: Uuid,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    user_id: Uuid,
    scope: &str,
    ttl_seconds: f64,
) -> Result<(), AppError> {
    // Codes are deleted on consumption, but an authorization the user abandons
    // leaves its row behind. Sweep expired rows here (cheap, and this endpoint
    // is rarely hit) so the table stays bounded without a background task.
    sqlx::query!("DELETE FROM oauth_codes WHERE expires_at < NOW()")
        .execute(&db.pool)
        .await?;

    sqlx::query!(
        "INSERT INTO oauth_codes \
         (id, code, client_id, redirect_uri, code_challenge, user_id, scope, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + make_interval(secs => $8::float8))",
        id,
        code,
        client_id,
        redirect_uri,
        code_challenge,
        user_id,
        scope,
        ttl_seconds,
    )
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Atomically consume an authorization code (delete-and-return), enforcing
/// single use even under concurrent token requests.
pub async fn take_code(db: &Database, code: &str) -> Result<Option<OAuthCodeEntity>, AppError> {
    let row = sqlx::query_as!(
        OAuthCodeEntity,
        r#"DELETE FROM oauth_codes WHERE code = $1
           RETURNING id, code, client_id, redirect_uri, code_challenge, user_id, scope,
                     expires_at as "expires_at: Ts""#,
        code
    )
    .fetch_optional(&db.pool)
    .await?;
    Ok(row)
}
