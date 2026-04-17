/// Result type alias for auth operations.
pub type AuthResult<T> = core::result::Result<T, AuthError>;

/// Auth-specific errors.
///
/// Dashboard's `Error` enum should add `AuthError(#[from] seggwat_auth::AuthError)`
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

    #[cfg(feature = "server")]
    #[error("GrpcError: {0}")]
    GrpcError(Box<tonic::Status>),

    #[cfg(feature = "server")]
    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("SerdeError: {0}")]
    SerdeError(#[from] serde_json::Error),
}

#[cfg(feature = "server")]
impl From<tonic::Status> for AuthError {
    fn from(status: tonic::Status) -> Self {
        AuthError::GrpcError(Box::new(status))
    }
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        use reqwest::StatusCode;

        let full_message = self.to_string();
        tracing::error!("AuthError: {full_message}");

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
            AuthError::GrpcError(_) => (
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
