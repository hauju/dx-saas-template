use std::time::Duration;

use mongodb::{Client, Collection, IndexModel, options::IndexOptions};

use crate::models::AppError;
use crate::models::api_key::ApiKeyEntity;
use crate::models::user::UserEntity;
use crate::server::oauth::store::{OAuthClientEntity, OAuthCodeEntity};

/// Typed MongoDB database wrapper.
#[derive(Clone)]
pub struct Database {
    pub users: Collection<UserEntity>,
    pub api_keys: Collection<ApiKeyEntity>,
    pub oauth_clients: Collection<OAuthClientEntity>,
    pub oauth_codes: Collection<OAuthCodeEntity>,
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
            api_keys: db.collection("api_keys"),
            oauth_clients: db.collection("oauth_clients"),
            oauth_codes: db.collection("oauth_codes"),
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

        // API key lookup by prefix (not unique: prefix collisions are resolved by
        // verifying the Argon2 hash) and listing by owner.
        self.api_keys
            .create_index(
                IndexModel::builder()
                    .keys(bson::doc! { "prefix": 1 })
                    .build(),
            )
            .await?;
        self.api_keys
            .create_index(
                IndexModel::builder()
                    .keys(bson::doc! { "user_id": 1 })
                    .build(),
            )
            .await?;

        // OAuth: unique client_id, unique single-use code, and a TTL that reaps
        // authorization codes at their `expires_at` instant.
        self.oauth_clients
            .create_index(
                IndexModel::builder()
                    .keys(bson::doc! { "client_id": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        self.oauth_codes
            .create_index(
                IndexModel::builder()
                    .keys(bson::doc! { "code": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        self.oauth_codes
            .create_index(
                IndexModel::builder()
                    .keys(bson::doc! { "expires_at": 1 })
                    .options(
                        IndexOptions::builder()
                            .expire_after(Duration::from_secs(0))
                            .build(),
                    )
                    .build(),
            )
            .await?;

        tracing::info!("Database indexes ensured");

        Ok(())
    }
}
