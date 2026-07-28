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

impl AppError {
    /// HTTP status this error should be reported as.
    ///
    /// Defined once, and deliberately not behind `#[cfg(feature = "server")]`:
    /// both the Axum response path and the server-function path need it, and
    /// having two copies is how they drift.
    pub fn status_code(&self) -> u16 {
        match self {
            AppError::NotFound => 404,
            AppError::Validation(_) => 400,
            AppError::Unauthorized => 401,
            AppError::Conflict(_) => 409,
            AppError::Internal(_) => 500,
            AppError::LimitExceeded(_) => 429,
            AppError::SubscriptionRequired(_) => 402,
        }
    }
}

impl From<AppError> for ServerFnError {
    fn from(err: AppError) -> Self {
        // Built directly rather than via `ServerFnError::new`, which hardcodes
        // 500. Without this every business-rule refusal — payment required, not
        // found, unauthorized — reaches the client as a server fault: the client
        // cannot tell "you need to upgrade" from "we broke", and the error is
        // logged at ERROR level as if something were wrong with the server.
        ServerFnError::ServerError {
            message: err.to_string(),
            code: err.status_code(),
            details: None,
        }
    }
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let status =
            StatusCode::from_u16(self.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn business_rule_refusals_keep_their_status_through_server_functions() {
        let cases = [
            (AppError::SubscriptionRequired("upgrade".into()), 402),
            (AppError::NotFound, 404),
            (AppError::Unauthorized, 401),
            (AppError::Conflict("exists".into()), 409),
            (AppError::Validation("bad".into()), 400),
            (AppError::LimitExceeded("slow down".into()), 429),
            (AppError::Internal("boom".into()), 500),
        ];

        for (err, expected) in cases {
            let text = err.to_string();
            match ServerFnError::from(err) {
                ServerFnError::ServerError { code, message, .. } => {
                    assert_eq!(code, expected, "wrong status for {message}");
                    assert_eq!(message, text);
                }
                other => panic!("expected a ServerError, got {other:?}"),
            }
        }
    }
}
