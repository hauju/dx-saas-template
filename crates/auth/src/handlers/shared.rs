//! Shared helpers for OIDC and Session API login flows.

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::state::AuthState;
use crate::types::{AuthUser, NewAuthUser};
use tracing::{info, warn};

/// Session key for storing the post-login redirect URL.
pub(crate) const LOGIN_REDIRECT_URL_SESSION_KEY: &str = "login.redirect.url";

/// User info extracted from OIDC userinfo or Zitadel session.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct AuthUserInfo {
    pub sub: String,
    pub nickname: Option<String>,
    pub name: Option<String>,
    pub email: String,
    pub picture: Option<String>,
    pub preferred_username: Option<String>,
}

/// Validate redirect URL to prevent open redirect attacks.
/// Only allows relative paths starting with `/` (no protocol-relative `//`).
pub(crate) fn is_safe_redirect_url(url: &str) -> bool {
    url.starts_with('/') && !url.starts_with("//")
}

/// Look up user by sub or email, migrate sub if needed, create if new.
/// Shared between OIDC callback and Session API login flows.
pub async fn lookup_or_create_user(
    auth_state: &AuthState,
    info: &AuthUserInfo,
) -> AuthResult<AuthUser> {
    // First try by OIDC subject ID (already migrated users)
    let user_by_sub = auth_state
        .user_store
        .get_user_by_sub(&info.sub)
        .await
        .map_err(|e| {
            warn!("Error fetching user by OIDC sub: {:?}", e);
            AuthError::ServerStateError("Failed to fetch user".to_string())
        })?;

    if let Some(user) = user_by_sub {
        info!("Existing user logged in (matched by sub)");
        return Ok(user);
    }

    // Try to find by email (Auth0 -> Zitadel migration case)
    let user_by_email = auth_state
        .user_store
        .get_user_by_email(&info.email)
        .await
        .map_err(|e| {
            warn!("Error fetching user by email: {:?}", e);
            AuthError::ServerStateError("Failed to fetch user".to_string())
        })?;

    if let Some(existing_user) = user_by_email {
        info!(
            "Migrating user {} from old IdP to Zitadel (updating sub)",
            existing_user.id
        );

        auth_state
            .user_store
            .update_user_sub(&existing_user.id, &info.sub)
            .await
            .map_err(|e| {
                warn!("Error updating user sub: {:?}", e);
                AuthError::ServerStateError("Failed to migrate user".to_string())
            })?;

        info!("Successfully migrated user sub to Zitadel");

        return Ok(AuthUser {
            sub: info.sub.clone(),
            ..existing_user
        });
    }

    // Completely new user - create them
    info!("User not found, creating new user...");

    let user = auth_state
        .user_store
        .create_user(NewAuthUser {
            sub: info.sub.clone(),
            email: info.email.clone(),
        })
        .await
        .map_err(|e| {
            warn!("Error creating user: {:?}", e);
            AuthError::ServerStateError("Failed to create user".to_string())
        })?;

    info!("New user created successfully");

    // Create a personal organization for the new user
    if let Err(e) = auth_state
        .user_store
        .create_personal_organization(&user.id, &info.email)
        .await
    {
        warn!("Failed to create personal organization: {:?}", e);
    } else {
        info!("Created personal organization for new user");
    }

    Ok(user)
}

/// Check subscriptions and determine redirect URL after login.
/// Shared between OIDC callback and Session API login flows.
pub async fn determine_post_login_redirect(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    user: &AuthUser,
) -> AuthResult<String> {
    // Check for a stored redirect URL in the session first
    let session_redirect = session
        .remove::<String>(LOGIN_REDIRECT_URL_SESSION_KEY)
        .await?
        .filter(|url| is_safe_redirect_url(url));

    // Delegate to the trait impl for org/subscription logic
    let redirect = auth_state
        .user_store
        .determine_post_login_redirect(&user.id, &auth_config.default_post_login_url)
        .await?;

    // Session redirect takes priority if the trait returned the default
    if redirect == auth_config.default_post_login_url
        && let Some(url) = session_redirect
    {
        return Ok(url);
    }

    Ok(redirect)
}
