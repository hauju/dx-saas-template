//! Trait abstractions for auth operations.
//!
//! These traits decouple the auth crate from `seggwat-app` (database, email, business logic).
//! The dashboard provides concrete implementations that wrap `AppState`.

use crate::error::AuthResult;
use crate::types::{AuthTosAcceptance, AuthUser, NewAuthUser};

/// User lookup, creation, migration, TOS, and post-login redirect.
///
/// Implemented by the dashboard to bridge `seggwat-core::User` ↔ `AuthUser`.
#[async_trait::async_trait]
pub trait AuthUserStore: Send + Sync + 'static {
    /// Find a user by their OIDC subject identifier.
    async fn get_user_by_sub(&self, sub: &str) -> AuthResult<Option<AuthUser>>;

    /// Find a user by email address.
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>>;

    /// Create a new user and return the created user (with generated ID).
    async fn create_user(&self, user: NewAuthUser) -> AuthResult<AuthUser>;

    /// Update a user's OIDC subject (IdP migration).
    async fn update_user_sub(&self, user_id: &str, new_sub: &str) -> AuthResult<()>;

    /// Create a personal organization for a newly registered user.
    async fn create_personal_organization(&self, user_id: &str, email: &str) -> AuthResult<()>;

    /// Update a user's TOS acceptance status.
    async fn update_tos_acceptance(&self, user_id: &str, tos: AuthTosAcceptance) -> AuthResult<()>;

    /// Determine the post-login redirect URL based on org/subscription state.
    ///
    /// `default_url` is the fallback if no special redirect is needed.
    async fn determine_post_login_redirect(
        &self,
        user_id: &str,
        default_url: &str,
    ) -> AuthResult<String>;
}

/// Sends verification emails (OTP codes).
///
/// Implemented by the dashboard to wrap SMTP/email service.
#[async_trait::async_trait]
pub trait AuthEmailSender: Send + Sync + 'static {
    /// Send a verification code email to the given address.
    async fn send_verification_code(
        &self,
        to_email: &str,
        code: &str,
        expires_in_minutes: u32,
    ) -> AuthResult<()>;
}
