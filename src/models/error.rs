use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum AppError {
    #[error("Not found")]
    NotFound,

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("Subscription required: {0}")]
    SubscriptionRequired(String),
}

impl From<AppError> for ServerFnError {
    fn from(err: AppError) -> Self {
        ServerFnError::new(err.to_string())
    }
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let status = match &self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::LimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::SubscriptionRequired(_) => StatusCode::PAYMENT_REQUIRED,
        };

        let body = serde_json::json!({
            "error": self.to_string(),
        });

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(feature = "server")]
impl From<mongodb::error::Error> for AppError {
    fn from(err: mongodb::error::Error) -> Self {
        tracing::error!("MongoDB error: {err}");
        AppError::Internal("Database error".to_string())
    }
}

#[cfg(feature = "server")]
impl From<bson::oid::Error> for AppError {
    fn from(err: bson::oid::Error) -> Self {
        AppError::Validation(format!("Invalid ID: {err}"))
    }
}
