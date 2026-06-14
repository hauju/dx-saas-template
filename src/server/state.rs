use std::sync::{Arc, OnceLock};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::models::AppError;
use crate::server::config::{Config, Secrets};
use crate::server::db::Database;

/// Global application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub secrets: Secrets,
    /// Shared JWKS cache for validating FerrisKey-issued bearer tokens. Held here
    /// so it's reused by both the auth router and the API dual-auth extractor.
    pub jwks: Arc<auth::JwksCache>,
}

static APP_STATE: OnceLock<AppState> = OnceLock::new();

impl AppState {
    /// Initialize the global AppState. Must be called once at startup.
    pub async fn init() -> Result<Self, AppError> {
        let config = Config::load_from_env()?;
        let secrets = Secrets::load_from_env()?;
        let db = Database::new(&config.db_url).await?;

        let jwks = Arc::new(auth::JwksCache::new(
            &config.ferriskey_url,
            config
                .ferriskey_issuer_url
                .as_deref()
                .unwrap_or(&config.ferriskey_url),
            &config.ferriskey_realm,
            &config.ferriskey_client_id,
        ));

        let state = Self {
            db,
            config,
            secrets,
            jwks,
        };

        APP_STATE
            .set(state.clone())
            .map_err(|_| AppError::Internal("AppState already initialized".to_string()))?;

        Ok(state)
    }

    /// Get a reference to the global AppState.
    /// Panics if `init()` was not called.
    #[allow(dead_code)]
    pub fn global() -> &'static Self {
        APP_STATE.get().expect("AppState not initialized")
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AppState {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, AppError> {
        parts
            .extensions
            .get::<AppState>()
            .cloned()
            .ok_or(AppError::Internal("AppState not in extensions".to_string()))
    }
}
