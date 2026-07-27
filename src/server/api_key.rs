//! API key store: mint, list, revoke, and verify `oat_` tokens.
//!
//! Only the Argon2 hash and an indexed lookup prefix are persisted. Verification
//! looks up candidates by prefix, then constant-time-verifies the hash — so a
//! leaked database never yields usable tokens.
//!
//! Queries use the `query_as!` / `query!` macros, so column names and types are
//! checked against the schema at compile time. Timestamps are written by the
//! database (`DEFAULT NOW()`, `SET … = NOW()`) and read back with `as "col: Ts"`
//! — the session store forces sqlx's `time` feature on, so without the
//! annotation the macros would map `TIMESTAMPTZ` to `time::OffsetDateTime`.

use uuid::Uuid;

use crate::models::AppError;
use crate::models::api_key::ApiKeyEntity;
use crate::server::db::Database;

/// Timestamp type for `TIMESTAMPTZ` columns — see the module docs.
type Ts = chrono::DateTime<chrono::Utc>;

/// Mint a new API key for `user_id`. Returns the plaintext token (shown once)
/// alongside the stored entity.
pub async fn create(
    db: &Database,
    user_id: Uuid,
    name: &str,
) -> Result<(String, ApiKeyEntity), AppError> {
    let token = crypto::generate_api_key()
        .map_err(|e| AppError::Internal(format!("token generation failed: {e}")))?;
    let prefix = crypto::api_key_prefix(&token)
        .ok_or_else(|| AppError::Internal("generated token has no valid prefix".to_string()))?;
    let hash = crypto::hash_secret(&token)
        .map_err(|e| AppError::Internal(format!("hashing failed: {e}")))?;

    let id = Uuid::new_v4();
    let name = name.trim().to_string();

    // `created_at` comes back from the database default, keeping its clock
    // authoritative — see the module docs.
    let created_at = sqlx::query_scalar!(
        r#"INSERT INTO api_keys (id, user_id, name, prefix, hash)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING created_at as "created_at: Ts""#,
        id,
        user_id,
        name,
        prefix,
        hash,
    )
    .fetch_one(&db.pool)
    .await?;

    let entity = ApiKeyEntity {
        id,
        user_id,
        name,
        prefix,
        hash,
        created_at,
        last_used_at: None,
        revoked_at: None,
    };

    Ok((token, entity))
}

/// List a user's non-revoked API keys, newest first.
pub async fn list(db: &Database, user_id: Uuid) -> Result<Vec<ApiKeyEntity>, AppError> {
    let rows = sqlx::query_as!(
        ApiKeyEntity,
        r#"SELECT id, user_id, name, prefix, hash,
                  created_at as "created_at: Ts",
                  last_used_at as "last_used_at: Ts",
                  revoked_at as "revoked_at: Ts"
           FROM api_keys WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC"#,
        user_id
    )
    .fetch_all(&db.pool)
    .await?;
    Ok(rows)
}

/// Revoke a key the user owns. Returns `true` if a matching active key was revoked.
pub async fn revoke(db: &Database, user_id: Uuid, key_id: Uuid) -> Result<bool, AppError> {
    let res = sqlx::query!(
        "UPDATE api_keys SET revoked_at = NOW() \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        key_id,
        user_id
    )
    .execute(&db.pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Resolve a presented token to its (active) key entity, or `None` if it doesn't
/// match. Updates `last_used_at` on success (best-effort).
pub async fn verify(db: &Database, token: &str) -> Result<Option<ApiKeyEntity>, AppError> {
    let Some(prefix) = crypto::api_key_prefix(token) else {
        return Ok(None);
    };

    let rows = sqlx::query_as!(
        ApiKeyEntity,
        r#"SELECT id, user_id, name, prefix, hash,
                  created_at as "created_at: Ts",
                  last_used_at as "last_used_at: Ts",
                  revoked_at as "revoked_at: Ts"
           FROM api_keys WHERE prefix = $1 AND revoked_at IS NULL"#,
        prefix
    )
    .fetch_all(&db.pool)
    .await?;

    for entity in rows {
        if crypto::verify_secret(&entity.hash, token) {
            // Best-effort usage stamp; never fail the request on this.
            if let Err(e) = sqlx::query!(
                "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                entity.id
            )
            .execute(&db.pool)
            .await
            {
                tracing::warn!("failed to update api key last_used_at: {e}");
            }
            return Ok(Some(entity));
        }
    }

    Ok(None)
}
