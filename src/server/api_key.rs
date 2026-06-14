//! API key store: mint, list, revoke, and verify `oat_` tokens.
//!
//! Only the Argon2 hash and an indexed lookup prefix are persisted. Verification
//! looks up candidates by prefix, then constant-time-verifies the hash — so a
//! leaked database never yields usable tokens.

use bson::oid::ObjectId;
use futures::TryStreamExt;

use crate::models::AppError;
use crate::models::api_key::ApiKeyEntity;
use crate::server::db::Database;

/// Mint a new API key for `user_id`. Returns the plaintext token (shown once)
/// alongside the stored entity.
pub async fn create(
    db: &Database,
    user_id: ObjectId,
    name: &str,
) -> Result<(String, ApiKeyEntity), AppError> {
    let token = crypto::generate_api_key()
        .map_err(|e| AppError::Internal(format!("token generation failed: {e}")))?;
    let prefix = crypto::api_key_prefix(&token)
        .ok_or_else(|| AppError::Internal("generated token has no valid prefix".to_string()))?;
    let hash = crypto::hash_secret(&token)
        .map_err(|e| AppError::Internal(format!("hashing failed: {e}")))?;

    let entity = ApiKeyEntity {
        id: ObjectId::new(),
        user_id,
        name: name.trim().to_string(),
        prefix,
        hash,
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
    };

    db.api_keys.insert_one(&entity).await?;
    Ok((token, entity))
}

/// List a user's non-revoked API keys, newest first.
pub async fn list(db: &Database, user_id: ObjectId) -> Result<Vec<ApiKeyEntity>, AppError> {
    let cursor = db
        .api_keys
        .find(bson::doc! { "user_id": user_id, "revoked_at": null })
        .sort(bson::doc! { "created_at": -1 })
        .await?;
    Ok(cursor.try_collect().await?)
}

/// Revoke a key the user owns. Returns `true` if a matching active key was revoked.
pub async fn revoke(db: &Database, user_id: ObjectId, key_id: ObjectId) -> Result<bool, AppError> {
    let res = db
        .api_keys
        .update_one(
            bson::doc! { "_id": key_id, "user_id": user_id, "revoked_at": null },
            bson::doc! { "$set": { "revoked_at": bson::DateTime::now() } },
        )
        .await?;
    Ok(res.modified_count > 0)
}

/// Resolve a presented token to its (active) key entity, or `None` if it doesn't
/// match. Updates `last_used_at` on success (best-effort).
pub async fn verify(db: &Database, token: &str) -> Result<Option<ApiKeyEntity>, AppError> {
    let Some(prefix) = crypto::api_key_prefix(token) else {
        return Ok(None);
    };

    let mut cursor = db
        .api_keys
        .find(bson::doc! { "prefix": &prefix, "revoked_at": null })
        .await?;

    while let Some(entity) = cursor.try_next().await? {
        if crypto::verify_secret(&entity.hash, token) {
            // Best-effort usage stamp; never fail the request on this.
            if let Err(e) = db
                .api_keys
                .update_one(
                    bson::doc! { "_id": entity.id },
                    bson::doc! { "$set": { "last_used_at": bson::DateTime::now() } },
                )
                .await
            {
                tracing::warn!("failed to update api key last_used_at: {e}");
            }
            return Ok(Some(entity));
        }
    }

    Ok(None)
}
