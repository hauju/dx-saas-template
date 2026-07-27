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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::test_support::seed_user;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn mints_a_token_whose_prefix_is_stored_but_whose_secret_is_not(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "mint").await;

        let (token, entity) = create(&db, user, "CLI").await.unwrap();

        assert!(
            token.starts_with("oat_"),
            "token should carry the scheme prefix"
        );
        assert_eq!(entity.prefix, crypto::api_key_prefix(&token).unwrap());
        // The whole point of the scheme: a database leak must not yield tokens.
        assert!(
            !entity.hash.contains(&token),
            "the raw token must never be stored"
        );
        assert_ne!(entity.hash, token);
        assert!(
            entity.created_at.timestamp() > 0,
            "created_at comes from the DB default"
        );
    }

    #[sqlx::test]
    async fn verify_matches_the_right_key_and_stamps_usage(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "verify").await;
        let (token, entity) = create(&db, user, "CLI").await.unwrap();

        assert!(
            entity.last_used_at.is_none(),
            "a fresh key has never been used"
        );

        let found = verify(&db, &token)
            .await
            .unwrap()
            .expect("token should verify");
        assert_eq!(found.id, entity.id);

        // The stamp is written after the match, so re-read to observe it.
        let stamped = verify(&db, &token).await.unwrap().unwrap();
        assert!(
            stamped.last_used_at.is_some(),
            "verify should stamp last_used_at"
        );
    }

    #[sqlx::test]
    async fn verify_rejects_unknown_and_malformed_tokens(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "reject").await;
        let (token, _) = create(&db, user, "CLI").await.unwrap();

        assert!(verify(&db, "not-an-oat-token").await.unwrap().is_none());
        assert!(
            verify(&db, "oat_completelyBogusValue")
                .await
                .unwrap()
                .is_none()
        );

        // Same prefix, wrong secret: the prefix narrows the search, the Argon2
        // hash is what actually authenticates. Swapping the tail must fail.
        let forged = format!("{}tampered", &token[..16]);
        assert!(verify(&db, &forged).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn revoked_keys_stop_verifying_and_stop_listing(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "revoke").await;
        let (token, entity) = create(&db, user, "CLI").await.unwrap();

        assert!(revoke(&db, user, entity.id).await.unwrap());
        assert!(
            verify(&db, &token).await.unwrap().is_none(),
            "revoked key must not authenticate"
        );
        assert!(list(&db, user).await.unwrap().is_empty());

        // Revoking again changes nothing, so it reports no rows affected.
        assert!(!revoke(&db, user, entity.id).await.unwrap());
    }

    #[sqlx::test]
    async fn a_user_cannot_revoke_another_users_key(pool: PgPool) {
        let db = Database::from_pool(pool);
        let owner = seed_user(&db, "owner").await;
        let attacker = seed_user(&db, "attacker").await;
        let (token, entity) = create(&db, owner, "CLI").await.unwrap();

        assert!(
            !revoke(&db, attacker, entity.id).await.unwrap(),
            "ownership must be enforced"
        );
        assert!(
            verify(&db, &token).await.unwrap().is_some(),
            "the key must still work"
        );
    }

    #[sqlx::test]
    async fn list_is_scoped_to_its_owner_and_newest_first(pool: PgPool) {
        let db = Database::from_pool(pool);
        let a = seed_user(&db, "list-a").await;
        let b = seed_user(&db, "list-b").await;

        create(&db, a, "first").await.unwrap();
        create(&db, a, "second").await.unwrap();
        create(&db, b, "other user's key").await.unwrap();

        let keys = list(&db, a).await.unwrap();
        assert_eq!(keys.len(), 2, "must not leak another user's keys");
        assert_eq!(keys[0].name, "second", "newest first");
        assert!(keys.iter().all(|k| k.user_id == a));
    }
}
