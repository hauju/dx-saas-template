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

/// A code about to be issued.
///
/// A struct rather than a positional argument list: four of these fields are
/// adjacent `&str`s, and swapping `redirect_uri` with `code_challenge` at a
/// call site would compile, pass tests that don't exercise the full exchange,
/// and quietly break PKCE. Named fields make that transposition impossible.
pub struct NewAuthorizationCode<'a> {
    pub id: Uuid,
    pub code: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub user_id: Uuid,
    pub scope: &'a str,
    /// How long the code stays valid; applied against the database clock.
    pub ttl_seconds: f64,
}

/// Mint an authorization code.
pub async fn insert_code(db: &Database, new: NewAuthorizationCode<'_>) -> Result<(), AppError> {
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
        new.id,
        new.code,
        new.client_id,
        new.redirect_uri,
        new.code_challenge,
        new.user_id,
        new.scope,
        new.ttl_seconds,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::test_support::seed_user;
    use sqlx::PgPool;

    fn client_id(n: &str) -> String {
        format!("mcp_test_{n}")
    }

    #[sqlx::test]
    async fn registers_a_client_and_round_trips_the_redirect_uri_array(pool: PgPool) {
        let db = Database::from_pool(pool);
        let uris = vec![
            "http://localhost:9999/callback".to_string(),
            "https://claude.ai/api/mcp/auth_callback".to_string(),
        ];

        let created = insert_client(
            &db,
            Uuid::new_v4(),
            &client_id("a"),
            &uris,
            Some("Test Client"),
        )
        .await
        .unwrap();
        assert!(
            created.created_at.timestamp() > 0,
            "created_at comes from the DB default"
        );

        let found = find_client(&db, &client_id("a")).await.unwrap().unwrap();
        // The allowlist is the security boundary for the whole OAuth flow, so
        // the TEXT[] must survive the round trip exactly — order included.
        assert_eq!(found.redirect_uris, uris);
        assert_eq!(found.client_name.as_deref(), Some("Test Client"));
        assert_eq!(found.id, created.id);
    }

    #[sqlx::test]
    async fn unknown_client_is_none(pool: PgPool) {
        let db = Database::from_pool(pool);
        assert!(
            find_client(&db, "mcp_never_registered")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[sqlx::test]
    async fn a_code_can_be_consumed_exactly_once(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "code").await;
        insert_code(
            &db,
            NewAuthorizationCode {
                id: Uuid::new_v4(),
                code: "code-1",
                client_id: &client_id("b"),
                redirect_uri: "http://cb",
                code_challenge: "challenge",
                user_id: user,
                scope: "mcp",
                ttl_seconds: 60.0,
            },
        )
        .await
        .unwrap();

        let first = take_code(&db, "code-1").await.unwrap();
        assert!(first.is_some(), "the first exchange succeeds");
        assert_eq!(first.unwrap().code_challenge, "challenge");

        // Replay must find nothing — this is what stops a stolen code being
        // redeemed twice.
        assert!(take_code(&db, "code-1").await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn concurrent_exchanges_of_one_code_yield_exactly_one_winner(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "race").await;
        insert_code(
            &db,
            NewAuthorizationCode {
                id: Uuid::new_v4(),
                code: "code-race",
                client_id: &client_id("c"),
                redirect_uri: "http://cb",
                code_challenge: "challenge",
                user_id: user,
                scope: "mcp",
                ttl_seconds: 60.0,
            },
        )
        .await
        .unwrap();

        // DELETE … RETURNING is atomic, so racing token requests can't both win.
        let (a, b) = tokio::join!(take_code(&db, "code-race"), take_code(&db, "code-race"));
        let winners = [a.unwrap().is_some(), b.unwrap().is_some()]
            .iter()
            .filter(|w| **w)
            .count();
        assert_eq!(winners, 1, "exactly one concurrent exchange may succeed");
    }

    #[sqlx::test]
    async fn inserting_a_code_sweeps_expired_ones(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "sweep").await;

        // A negative TTL lands in the past, standing in for a code whose
        // authorization was started and then abandoned.
        insert_code(
            &db,
            NewAuthorizationCode {
                id: Uuid::new_v4(),
                code: "stale",
                client_id: &client_id("d"),
                redirect_uri: "http://cb",
                code_challenge: "ch",
                user_id: user,
                scope: "mcp",
                ttl_seconds: -1.0,
            },
        )
        .await
        .unwrap();
        insert_code(
            &db,
            NewAuthorizationCode {
                id: Uuid::new_v4(),
                code: "fresh",
                client_id: &client_id("d"),
                redirect_uri: "http://cb",
                code_challenge: "ch",
                user_id: user,
                scope: "mcp",
                ttl_seconds: 60.0,
            },
        )
        .await
        .unwrap();

        // Mongo's TTL index used to reap these; the sweep on insert replaces it.
        let remaining: Vec<String> = sqlx::query_scalar("SELECT code FROM oauth_codes")
            .fetch_all(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            vec!["fresh"],
            "the abandoned code must not accumulate"
        );
    }

    #[sqlx::test]
    async fn deleting_a_user_takes_their_codes_with_them(pool: PgPool) {
        let db = Database::from_pool(pool);
        let user = seed_user(&db, "cascade").await;
        insert_code(
            &db,
            NewAuthorizationCode {
                id: Uuid::new_v4(),
                code: "c",
                client_id: &client_id("e"),
                redirect_uri: "http://cb",
                code_challenge: "ch",
                user_id: user,
                scope: "mcp",
                ttl_seconds: 60.0,
            },
        )
        .await
        .unwrap();

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&db.pool)
            .await
            .unwrap();

        // ON DELETE CASCADE: no orphaned credentials outliving their owner.
        assert!(take_code(&db, "c").await.unwrap().is_none());
    }
}
