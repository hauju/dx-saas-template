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

/// Whether any user exists yet — dx-auth's first-run bootstrap check.
pub async fn any_exist(db: &Database) -> Result<bool, AppError> {
    let exists = sqlx::query_scalar!(r#"SELECT EXISTS(SELECT 1 FROM users) AS "exists!""#)
        .fetch_one(&db.pool)
        .await?;
    Ok(exists)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::test_support::seed_user;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn finds_a_user_by_id_sub_and_email(pool: PgPool) {
        let db = Database::from_pool(pool);
        let id = seed_user(&db, "lookup").await;

        let by_id = find_by_id(&db, id).await.unwrap().expect("found by id");
        assert_eq!(by_id.sub, "sub-lookup");
        assert_eq!(by_id.email, "lookup@example.test");
        assert!(
            by_id.subscription.is_none(),
            "a new user has no subscription"
        );

        assert_eq!(
            find_by_sub(&db, "sub-lookup").await.unwrap().unwrap().id,
            id
        );
        assert_eq!(
            find_by_email(&db, "lookup@example.test")
                .await
                .unwrap()
                .unwrap()
                .id,
            id
        );
    }

    #[sqlx::test]
    async fn missing_users_are_none_not_errors(pool: PgPool) {
        let db = Database::from_pool(pool);
        assert!(find_by_id(&db, Uuid::new_v4()).await.unwrap().is_none());
        assert!(find_by_sub(&db, "nobody").await.unwrap().is_none());
        assert!(
            find_by_email(&db, "nobody@example.test")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[sqlx::test]
    async fn decodes_the_jsonb_subscription_column(pool: PgPool) {
        let db = Database::from_pool(pool);
        let id = seed_user(&db, "sub").await;

        let info = SubscriptionInfo {
            subscription_id: "sub_123".to_string(),
            customer_id: "cus_456".to_string(),
            status: "active".to_string(),
            tier: Some("pro".to_string()),
            current_period_end: Some(1_798_761_600_000),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        sqlx::query("UPDATE users SET subscription = $1 WHERE id = $2")
            .bind(sqlx::types::Json(&info))
            .bind(id)
            .execute(&db.pool)
            .await
            .unwrap();

        // JSONB → Json<SubscriptionInfo> is easy to get wrong (the macro would
        // otherwise hand back a bare serde_json::Value), so assert the shape.
        let stored = find_by_id(&db, id)
            .await
            .unwrap()
            .unwrap()
            .subscription
            .unwrap();
        assert_eq!(stored, info);
        assert!(stored.is_active());
    }

    #[sqlx::test]
    async fn sub_and_email_are_unique(pool: PgPool) {
        let db = Database::from_pool(pool);
        seed_user(&db, "dupe").await;

        // The constraints behind the login-race handling in auth_store.
        let same_email = sqlx::query("INSERT INTO users (id, sub, email) VALUES ($1, $2, $3)")
            .bind(Uuid::new_v4())
            .bind("sub-other")
            .bind("dupe@example.test")
            .execute(&db.pool)
            .await;
        assert!(same_email.is_err(), "a duplicate email must be rejected");

        let same_sub = sqlx::query("INSERT INTO users (id, sub, email) VALUES ($1, $2, $3)")
            .bind(Uuid::new_v4())
            .bind("sub-dupe")
            .bind("other@example.test")
            .execute(&db.pool)
            .await;
        assert!(same_sub.is_err(), "a duplicate sub must be rejected");
    }

    #[sqlx::test]
    async fn a_unique_violation_maps_to_conflict_not_internal(pool: PgPool) {
        let db = Database::from_pool(pool);
        seed_user(&db, "conflict").await;

        let err = sqlx::query("INSERT INTO users (id, sub, email) VALUES ($1, $2, $3)")
            .bind(Uuid::new_v4())
            .bind("sub-conflict")
            .bind("other@example.test")
            .execute(&db.pool)
            .await
            .unwrap_err();

        // 409, not 500 — the caller asked for something that already exists.
        assert!(matches!(AppError::from(err), AppError::Conflict(_)));
    }
}
