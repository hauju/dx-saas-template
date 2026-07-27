//! Logout handler.

use axum::Extension;
use axum::response::{IntoResponse, Redirect, Response};

use crate::config::AuthConfig;
use crate::error::AuthResult;
use crate::session::LoggedInData;
use crate::session::login::LOGGED_IN_USER_SESSION_KEY;

/// Handler to run when the user wants to logout.
///
/// Behaviour depends on how the user logged in (encoded in `id_token`):
/// - `"dev_mode_token"` → redirect to `AuthConfig.dev_login_url`
/// - otherwise → redirect to `AuthConfig.login_page_url`
pub async fn logout(
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
) -> AuthResult<Response> {
    // Read login data before flushing the entire session
    let login_data = session
        .get::<LoggedInData>(LOGGED_IN_USER_SESSION_KEY)
        .await?;

    // Flush the session: removes all data AND deletes it from the session store.
    // This is stronger than remove() which only deletes one key but leaves
    // the session ID valid in the store.
    session.flush().await?;

    if let Some(login_data) = login_data {
        if login_data.id_token == "dev_mode_token" {
            Ok(Redirect::to(&auth_config.dev_login_url).into_response())
        } else {
            Ok(Redirect::to(&auth_config.login_page_url).into_response())
        }
    } else {
        Ok(Redirect::to("/").into_response())
    }
}
