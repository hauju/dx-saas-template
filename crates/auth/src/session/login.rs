//! Login helper: set session data.

use crate::error::{AuthError, AuthResult};
use crate::session::LoggedInData;

pub const LOGGED_IN_USER_SESSION_KEY: &str = "logged_in_data";

/// Helper function to log the user in by setting the session data.
pub async fn login(session: &tower_sessions::Session, data: &LoggedInData) -> AuthResult<()> {
    session
        .insert(LOGGED_IN_USER_SESSION_KEY, data)
        .await
        .map_err(AuthError::from)?;
    Ok(())
}
