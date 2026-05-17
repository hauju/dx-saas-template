//! Shared helpers for OIDC and Session API login flows.

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::state::AuthState;
use crate::types::{AuthUser, NewAuthUser};
use tracing::{info, warn};

/// Session key for storing the post-login redirect URL.
pub(crate) const LOGIN_REDIRECT_URL_SESSION_KEY: &str = "login.redirect.url";

/// User info extracted from OIDC userinfo or FerrisKey session.
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

/// Quick email-format check. Returns `true` for plausibly-deliverable addresses.
///
/// Catches the common garbage we've seen hit downstream mailers: missing/multiple
/// `@`, empty or over-long parts, consecutive dots, leading/trailing dots, and
/// domains with no TLD. This is intentionally a shape check — not an RFC 5321
/// parser — just enough to reject input before we spend cycles on CAPTCHA, OTP
/// generation, and SMTP.
pub fn is_valid_email(email: &str) -> bool {
    if email.len() < 3 || email.len() > 320 {
        return false;
    }

    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };

    // Exactly one '@'
    if domain.contains('@') {
        return false;
    }

    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if domain.is_empty() || domain.len() > 255 {
        return false;
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }

    // Domain must have a TLD
    if !domain.contains('.') {
        return false;
    }

    // Rough character sanity — local part allows RFC-5322 atext + dot;
    // domain is limited to LDH (letters, digits, hyphen, dot).
    let local_ok = local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-.".contains(&b));
    if !local_ok {
        return false;
    }

    let domain_ok = domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if !domain_ok {
        return false;
    }

    // No label may start/end with hyphen or be empty
    domain
        .split('.')
        .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
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

    // Try to find by email (IdP migration case, e.g. Auth0/Zitadel -> FerrisKey)
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
            "Migrating user {} from old IdP to FerrisKey (updating sub)",
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

        info!("Successfully migrated user sub to FerrisKey");

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

#[cfg(test)]
mod tests {
    use super::is_valid_email;

    #[test]
    fn accepts_normal_emails() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("a.b.c@sub.example.co.uk"));
        assert!(is_valid_email("user+tag@example.com"));
    }

    #[test]
    fn rejects_consecutive_dots() {
        // The real-world address that triggered this check.
        assert!(!is_valid_email("q.u.i.n.t.on..kellam@gmail.com"));
        assert!(!is_valid_email("a..b@example.com"));
        assert!(!is_valid_email("a@example..com"));
    }

    #[test]
    fn rejects_malformed() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("two@at@signs.com"));
        assert!(!is_valid_email(".leading@example.com"));
        assert!(!is_valid_email("trailing.@example.com"));
        assert!(!is_valid_email("user@nodotdomain"));
        assert!(!is_valid_email("user@-bad.com"));
        assert!(!is_valid_email("user@bad-.com"));
    }
}
