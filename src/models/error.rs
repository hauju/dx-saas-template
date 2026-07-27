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

    #[error("Conflict: {0}")]
    Conflict(String),

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
            AppError::Conflict(_) => StatusCode::CONFLICT,
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
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        // A unique violation means the caller asked for something that already
        // exists — a conflict, not a server fault, and worth a distinguishable
        // status. Everything else stays opaque on purpose: database messages
        // name tables, columns, and constraints, which is not detail to hand
        // back over HTTP. The specifics go to the log.
        if let sqlx::Error::Database(ref db_err) = err
            && db_err.is_unique_violation()
        {
            tracing::warn!("PostgreSQL unique violation: {err}");
            return AppError::Conflict("That already exists.".to_string());
        }

        tracing::error!("PostgreSQL error: {err}");
        AppError::Internal("Database error".to_string())
    }
}

#[cfg(feature = "server")]
impl From<uuid::Error> for AppError {
    fn from(err: uuid::Error) -> Self {
        AppError::Validation(format!("Invalid ID: {err}"))
    }
}
