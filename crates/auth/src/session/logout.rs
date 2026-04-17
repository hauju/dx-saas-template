//! Logout handler.

use axum::Extension;
use axum::response::{IntoResponse, Redirect, Response};

use crate::config::AuthConfig;
use crate::error::AuthResult;

/// Handler to run when the user wants to logout.
///
/// Flushes the session and redirects to the login page.
pub async fn logout(
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
) -> AuthResult<Response> {
    // Flush the session: removes all data AND deletes it from the store (Redis).
    // This is stronger than remove() which only deletes one key but leaves
    // the session ID valid in Redis.
    session.flush().await?;

    Ok(Redirect::to(&auth_config.login_page_url).into_response())
}
