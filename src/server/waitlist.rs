//! Waitlist store: the one unauthenticated write in the app.

use crate::models::AppError;
use crate::server::db::Database;

/// Add `email` to the waitlist, or note that they asked again.
///
/// Takes an address `models::waitlist::validate_email` has already
/// normalised: an un-normalised key here is a duplicate person in the queue.
pub async fn join(db: &Database, email: &str) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO waitlist (email) VALUES ($1)
         ON CONFLICT (email) DO UPDATE SET updated_at = NOW()",
        email
    )
    .execute(&db.pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn one_address_is_one_row_however_often_it_asks(pool: PgPool) {
        let db = Database::from_pool(pool.clone());
        join(&db, "ada@example.test").await.unwrap();
        join(&db, "ada@example.test").await.unwrap();

        let rows: Vec<(String, bool)> =
            sqlx::query_as("SELECT email, updated_at >= created_at FROM waitlist")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rows, vec![("ada@example.test".to_string(), true)]);
    }
}
