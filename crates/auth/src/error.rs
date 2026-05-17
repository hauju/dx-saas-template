/// Result type alias for auth operations.
pub type AuthResult<T> = core::result::Result<T, AuthError>;

/// Auth-specific errors.
///
/// Dashboard's `Error` enum should add `AuthError(#[from] auth::AuthError)`
/// and delegate the `IntoResponse` conversion for auth error variants.
#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    Unauthorized(String),

    #[error("UserNotLoggedIn")]
    UserNotLoggedIn,

    #[error("ServerStateError: {0}")]
    ServerStateError(String),

    #[error("AuthSessionLayerNotFound: {0}")]
    AuthSessionLayerNotFound(String),

    #[cfg(feature = "server")]
    #[error("SessionError: {0}")]
    SessionError(#[from] tower_sessions::session::Error),

    /// Non-2xx response from FerrisKey. Carries the HTTP status and a body
    /// snippet for tracing.
    #[cfg(feature = "server")]
    #[error("FerrisKeyError: {status} — {body}")]
    FerrisKeyError {
        status: reqwest::StatusCode,
        body: String,
    },

    #[cfg(feature = "server")]
    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("SerdeError: {0}")]
    SerdeError(#[from] serde_json::Error),
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        use reqwest::StatusCode;

        let full_message = self.to_string();

        // Only log internal errors at ERROR level (→ Sentry event via tracing layer)
        // Client/auth errors at WARN level (→ breadcrumb only)
        if self.is_internal_error() {
            tracing::error!("AuthError (internal): {full_message}");
        } else {
            tracing::warn!("AuthError: {full_message}");
        }

        match self {
            AuthError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg).into_response(),
            AuthError::UserNotLoggedIn => {
                (StatusCode::UNAUTHORIZED, "Not logged in").into_response()
            }
            AuthError::ServerStateError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server configuration error",
            )
                .into_response(),
            AuthError::AuthSessionLayerNotFound(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication system error",
            )
                .into_response(),
            AuthError::SessionError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session management error",
            )
                .into_response(),
            AuthError::FerrisKeyError { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An error occurred while communicating with an external service",
            )
                .into_response(),
            AuthError::ReqwestError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An error occurred while communicating with an external service",
            )
                .into_response(),
            AuthError::SerdeError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Data processing error").into_response()
            }
        }
    }
}

#[cfg(feature = "server")]
impl AuthError {
    /// Returns true for server-side errors that should be reported to Sentry.
    /// Client/auth errors (bad credentials, expired sessions) are expected and not actionable.
    fn is_internal_error(&self) -> bool {
        matches!(
            self,
            AuthError::ServerStateError(_)
                | AuthError::AuthSessionLayerNotFound(_)
                | AuthError::SessionError(_)
                | AuthError::FerrisKeyError { .. }
                | AuthError::ReqwestError(_)
                | AuthError::SerdeError(_)
        )
    }
}
