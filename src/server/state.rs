use std::sync::OnceLock;

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
}

static APP_STATE: OnceLock<AppState> = OnceLock::new();

impl AppState {
    /// Initialize the global AppState. Must be called once at startup.
    pub async fn init() -> Result<Self, AppError> {
        let config = Config::load_from_env()?;
        let secrets = Secrets::load_from_env()?;
        let db = Database::new(&config.db_url).await?;

        let state = Self {
            db,
            config,
            secrets,
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
