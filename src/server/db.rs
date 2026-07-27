use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::models::AppError;

/// Typed PostgreSQL pool wrapper.
#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

impl Database {
    pub async fn new(db_url: &str) -> Result<Self, AppError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(db_url)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to PostgreSQL: {e}")))?;

        // Ping to verify connection.
        sqlx::query("SELECT 1")
            .execute(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to ping PostgreSQL: {e}")))?;

        tracing::info!("Connected to database successfully");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to run migrations: {e}")))?;

        tracing::info!("Database migrations applied");

        Ok(Self { pool })
    }
}
