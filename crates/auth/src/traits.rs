//! Trait abstractions for auth operations.
//!
//! These traits decouple the auth crate from the host application (database, email, business logic).
//! The host app provides concrete implementations that wrap `AppState`.

use crate::error::AuthResult;
use crate::types::{AuthTosAcceptance, AuthUser, NewAuthUser};

/// User lookup, creation, migration, TOS, and post-login redirect.
///
/// Implemented by the host app to bridge its `User` type ↔ `AuthUser`.
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

    /// Record that the given user has just successfully logged in.
    /// Default implementation is a no-op so older `AuthUserStore` impls
    /// keep compiling; the dashboard may override it to bump
    /// `users.last_login_at`. Errors here are logged but should never
    /// fail the login flow.
    async fn record_login(&self, _user_id: &str) -> AuthResult<()> {
        Ok(())
    }
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

/// Backs auth rate limiting with shared storage so the quota holds across
/// replicas.
///
/// Optional: when no store is supplied on [`crate::AuthState`], the router falls
/// back to an in-process limiter, which is correct for a single instance but
/// allows N× the quota across N replicas.
///
/// Kept as a trait (rather than taking a database handle) so this crate stays
/// independent of the host application's storage layer.
#[async_trait::async_trait]
pub trait AuthRateLimitStore: Send + Sync + 'static {
    /// Record a request against `key` and report whether it is within quota.
    ///
    /// The quota itself belongs to the implementation. Implementations should
    /// decide deliberately whether to fail open or closed when their backing
    /// store is unavailable, and document the choice.
    async fn check(&self, key: &str) -> bool;
}
