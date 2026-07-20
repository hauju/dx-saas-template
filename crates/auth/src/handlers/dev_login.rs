//! Development-only login bypass.
//!
//! Signs in as a fixed local user without going through FerrisKey, so you can
//! iterate on authenticated pages without a running IdP. The session it creates
//! carries `id_token = "dev_mode_token"`, which [`crate::session::logout`] uses
//! to route logout back to the dev login page.
//!
//! # Production safety
//!
//! This is guarded by two independent gates, either of which is sufficient:
//! 1. **Compile-time:** the whole module — handler and route — is behind
//!    `#[cfg(debug_assertions)]`, so `dx build --release` (which turns debug
//!    assertions off) omits it from the production binary entirely.
//! 2. **Runtime:** even in a debug build the handler stays inert unless
//!    `DEV_LOGIN=true` is set in the environment.

use axum::Extension;
use axum::response::{IntoResponse, Redirect, Response};

use super::{AuthUserInfo, lookup_or_create_user};
use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::session::{LoggedInData, login};
use crate::state::AuthState;

/// Fixed identity the dev login signs in as.
const DEV_SUB: &str = "dev-mode-user";
const DEV_EMAIL: &str = "dev@localhost";
const DEV_USERNAME: &str = "dev";

/// `POST /auth/dev-login` — sign in as the local dev user, bypassing FerrisKey.
///
/// Only present in debug builds, and only active when `DEV_LOGIN=true`.
pub async fn dev_login_handler(
    Extension(auth_config): Extension<AuthConfig>,
    Extension(auth_state): Extension<AuthState>,
    session: tower_sessions::Session,
) -> AuthResult<Response> {
    if std::env::var("DEV_LOGIN").as_deref() != Ok("true") {
        return Err(AuthError::Unauthorized("Dev login is disabled".to_string()));
    }

    let info = AuthUserInfo {
        sub: DEV_SUB.to_string(),
        nickname: None,
        name: Some("Dev User".to_string()),
        email: DEV_EMAIL.to_string(),
        picture: None,
        preferred_username: Some(DEV_USERNAME.to_string()),
    };

    let user = lookup_or_create_user(&auth_state, &info).await?;

    // Rotate the session id to avoid fixation, matching the real login flow.
    session.cycle_id().await?;

    let data = LoggedInData {
        id: user.id,
        sub: user.sub,
        email: user.email,
        username: DEV_USERNAME.to_string(),
        avatar_url: None,
        id_token: "dev_mode_token".to_string(),
    };
    login(&session, &data).await?;

    tracing::warn!("Dev login used — signed in as {DEV_EMAIL}");

    Ok(Redirect::to(&auth_config.default_post_login_url).into_response())
}
