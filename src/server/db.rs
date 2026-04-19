use mongodb::{Client, Collection, IndexModel, options::IndexOptions};

use crate::models::AppError;
use crate::models::user::UserEntity;

/// Typed MongoDB database wrapper.
#[derive(Clone)]
pub struct Database {
    pub users: Collection<UserEntity>,
}

impl Database {
    pub async fn new(db_url: &str) -> Result<Self, AppError> {
        let client = Client::with_uri_str(db_url)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to MongoDB: {e}")))?;

        let db = client.database("dx_saas");

        // Ping to verify connection
        db.run_command(bson::doc! { "ping": 1 })
            .await
            .map_err(|e| AppError::Internal(format!("Failed to ping MongoDB: {e}")))?;

        tracing::info!("Connected to database successfully");

        let database = Self {
            users: db.collection("users"),
        };

        database.ensure_indexes().await?;

        Ok(database)
    }

    async fn ensure_indexes(&self) -> Result<(), AppError> {
        // Unique index on sub
        self.users
            .create_index(
                IndexModel::builder()
                    .keys(bson::doc! { "sub": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;

        // Unique index on email
        self.users
            .create_index(
                IndexModel::builder()
                    .keys(bson::doc! { "email": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;

        tracing::info!("Database indexes ensured");

        Ok(())
    }
}
