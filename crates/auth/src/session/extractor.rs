//! UserSession extractor and LoggedInData type.

use crate::error::AuthError;
use crate::session::login::LOGGED_IN_USER_SESSION_KEY;

use axum::http::request::Parts;

/// Session data available to the backend when the user is logged in.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggedInData {
    pub id: String,
    pub sub: String,
    pub email: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub id_token: String,
}

/// Used for extracting in the server functions.
/// If the `data` is `Some`, the user is logged in.
#[derive(Clone)]
pub struct UserSession {
    data: Option<LoggedInData>,
}

impl UserSession {
    /// Get the [`LoggedInData`].
    ///
    /// Raises a [`AuthError::UserNotLoggedIn`] error if the user is not logged in.
    pub fn data(self) -> Result<LoggedInData, AuthError> {
        self.data.ok_or(AuthError::UserNotLoggedIn)
    }
}

impl<S> axum::extract::FromRequestParts<S> for UserSession
where
    S: std::marker::Sync + std::marker::Send,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, AuthError> {
        let session = parts
            .extensions
            .get::<tower_sessions::Session>()
            .cloned()
            .ok_or(AuthError::AuthSessionLayerNotFound(
                "Auth Session Layer not found".to_string(),
            ))?;

        let data: Option<LoggedInData> = session
            .get::<LoggedInData>(LOGGED_IN_USER_SESSION_KEY)
            .await?;

        Ok(Self { data })
    }
}
