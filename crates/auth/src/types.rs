//! Auth-owned domain types.
//!
//! These decouple the auth crate from the host application's domain types.
//! The host app's trait implementations convert between these and
//! the core `User`/`UserToCreate`/`UserTosAcceptance` types.

use serde::{Deserialize, Serialize};

/// Authenticated user returned from store operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: String,
    pub sub: String,
    pub email: String,
    pub display_name: Option<String>,
    pub tos_acceptance: Option<AuthTosAcceptance>,
}

/// Data needed to create a new user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuthUser {
    pub sub: String,
    pub email: String,
}

/// Terms of Service acceptance record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthTosAcceptance {
    pub latest_version: String,
    pub accepted: bool,
}

/// A registered passkey (WebAuthn credential).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyInfo {
    pub id: String,
    pub name: String,
}

/// Trigger to tell the App to re-fetch user login data.
///
/// Used by the login page after successful authentication to signal the App
/// component to re-run `get_login_data()`, which picks up the new session cookie
/// and transitions `UserAuthState` to `Authenticated` — enabling client-side
/// navigation instead of a full page reload.
#[derive(Clone, Copy, Default)]
pub struct UserDataRefreshTrigger(pub u32);
