//! User store: read helpers shared by auth, API auth, billing, and the
//! subscription endpoints. Centralises the `users` row → [`UserEntity`] mapping
//! (including the JSONB `subscription` column) so it lives in one place.
//!
//! Queries use the `query_as!` macro, so column names and types are checked
//! against the schema at compile time. Two annotations are needed:
//!
//! - `subscription: Json<SubscriptionInfo>` decodes the JSONB column into the
//!   field's declared type instead of a generic `serde_json::Value`.
//! - `created_at`/`updated_at: Ts` pins `TIMESTAMPTZ` to chrono. The session
//!   store enables sqlx's `time` feature, and because Cargo unifies features
//!   the macro would otherwise map timestamps to `time::OffsetDateTime`.

use sqlx::types::Json;
use uuid::Uuid;

use crate::models::AppError;
use crate::models::subscription::SubscriptionInfo;
use crate::models::user::UserEntity;
use crate::server::db::Database;

/// Timestamp type for `TIMESTAMPTZ` columns — see the module docs.
type Ts = chrono::DateTime<chrono::Utc>;

/// Row shape shared by the lookups below.
///
/// Separate from [`UserEntity`] only because the macro needs to decode
/// `subscription` as `Json<T>` before it is unwrapped.
struct UserRow {
    id: Uuid,
    sub: String,
    email: String,
    name: Option<String>,
    avatar_url: Option<String>,
    subscription: Option<Json<SubscriptionInfo>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserRow> for UserEntity {
    fn from(r: UserRow) -> Self {
        Self {
            id: r.id,
            sub: r.sub,
            email: r.email,
            name: r.name,
            avatar_url: r.avatar_url,
            subscription: r.subscription.map(|j| j.0),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

pub async fn find_by_id(db: &Database, id: Uuid) -> Result<Option<UserEntity>, AppError> {
    let row = sqlx::query_as!(
        UserRow,
        r#"SELECT id, sub, email, name, avatar_url,
                  subscription as "subscription: Json<SubscriptionInfo>",
                  created_at as "created_at: Ts", updated_at as "updated_at: Ts"
           FROM users WHERE id = $1"#,
        id
    )
    .fetch_optional(&db.pool)
    .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_sub(db: &Database, sub: &str) -> Result<Option<UserEntity>, AppError> {
    let row = sqlx::query_as!(
        UserRow,
        r#"SELECT id, sub, email, name, avatar_url,
                  subscription as "subscription: Json<SubscriptionInfo>",
                  created_at as "created_at: Ts", updated_at as "updated_at: Ts"
           FROM users WHERE sub = $1"#,
        sub
    )
    .fetch_optional(&db.pool)
    .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_email(db: &Database, email: &str) -> Result<Option<UserEntity>, AppError> {
    let row = sqlx::query_as!(
        UserRow,
        r#"SELECT id, sub, email, name, avatar_url,
                  subscription as "subscription: Json<SubscriptionInfo>",
                  created_at as "created_at: Ts", updated_at as "updated_at: Ts"
           FROM users WHERE email = $1"#,
        email
    )
    .fetch_optional(&db.pool)
    .await?;
    Ok(row.map(Into::into))
}
