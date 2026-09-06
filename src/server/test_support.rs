//! Shared fixtures for the database-backed tests.
//!
//! These tests run against a real PostgreSQL instance rather than a mock: the
//! behaviour worth protecting here lives in the database itself — unique
//! constraints, `ON CONFLICT` arithmetic, `DELETE … RETURNING` atomicity,
//! JSONB round-trips, timestamp defaults — and none of it survives being
//! stubbed out.
//!
//! `#[sqlx::test]` gives each case its own freshly migrated database, so tests
//! are isolated and can run in parallel. They need a reachable server:
//!
//! ```sh
//! docker compose up -d
//! cargo test -p dx-saas-template --no-default-features --features server
//! ```
//!
//! `DATABASE_URL` from `.env` points at it; without a server these tests fail
//! rather than silently skip.

use std::sync::Arc;

use uuid::Uuid;

use crate::server::config::{Config, Secrets};
use crate::server::db::Database;
use crate::server::state::AppState;

/// Build an `AppState` around a test database.
///
/// Deliberately does not touch `AppState::init`, which stores the state in a
/// process-wide `OnceLock` — that would let only one test have a database.
/// Constructing the struct directly keeps every case independent.
///
/// The external endpoints are unreachable placeholders: nothing under test
/// dials FerrisKey or SMTP, and a test that started to would fail loudly rather
/// than quietly reaching a real service.
pub fn test_state(db: Database) -> AppState {
    let config = Config {
        db_url: "postgres://test".to_string(),
        base_url: "http://localhost:8099".to_string(),
        ferriskey_url: "http://127.0.0.1:1".to_string(),
        ferriskey_issuer_url: None,
        ferriskey_realm: "test".to_string(),
        ferriskey_client_id: "test-client".to_string(),
        secure_cookies: false,
        trust_proxy_headers: false,
        smtp_host: "127.0.0.1".to_string(),
        smtp_port: 1,
        smtp_from: "test@example.test".to_string(),
        smtp_security: smtp::SmtpSecurity::None,
        open_registration: false,
        allowed_registration_emails: Vec::new(),
        allowed_registration_domains: Vec::new(),
        captcha: None,
        coming_soon: false,
    };

    let secrets = Secrets {
        session_secret: vec![0u8; 64],
        encryption_key: None,
        ferriskey_client_secret: None,
        smtp_user: secrecy::SecretString::from(String::new()),
        smtp_password: secrecy::SecretString::from(String::new()),
        polar_access_token: None,
        polar_webhook_secret: None,
        captcha_secret_key: None,
    };

    let jwks = Arc::new(auth::JwksCache::new(
        &config.ferriskey_url,
        &config.ferriskey_url,
        &config.ferriskey_realm,
        &config.ferriskey_client_id,
    ));

    AppState {
        db,
        config,
        secrets,
        jwks,
    }
}

/// Insert a user and return its id.
///
/// Most stores hang off `users` by foreign key, so almost every case needs one.
/// `discriminator` keeps `sub`/`email` unique within a test that needs several.
/// Fixtures use the runtime query API rather than the `query!` macro on
/// purpose: macro queries are baked into the committed `.sqlx` metadata, and
/// test-only SQL does not belong there. These run against a real database, so a
/// broken fixture query fails the test that uses it.
pub async fn seed_user(db: &Database, discriminator: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, sub, email) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("sub-{discriminator}"))
        .bind(format!("{discriminator}@example.test"))
        .execute(&db.pool)
        .await
        .expect("seed_user failed");
    id
}
