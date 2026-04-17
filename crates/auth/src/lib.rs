//! SeggWat authentication crate.
//!
//! Provides Zitadel Session API v2 and WebAuthn integration
//! as a reusable workspace crate.
//!
//! This crate is independent of `seggwat-app` and `seggwat-core`.
//! The dashboard provides trait implementations via `AuthUserStore`
//! and `AuthEmailSender` to bridge auth ↔ business logic.

mod config;
mod error;
pub mod types;

pub use config::AuthConfig;
pub use error::{AuthError, AuthResult};
pub use types::UserDataRefreshTrigger;

#[cfg(feature = "server")]
pub mod traits;

#[cfg(feature = "server")]
pub mod state;

#[cfg(feature = "server")]
pub use state::AuthState;

#[cfg(feature = "server")]
pub use traits::{AuthEmailSender, AuthUserStore};

#[cfg(feature = "server")]
pub mod zitadel;

#[cfg(feature = "server")]
pub mod session;

#[cfg(feature = "server")]
pub mod handlers;

#[cfg(feature = "server")]
pub mod csrf;

#[cfg(feature = "server")]
pub mod rate_limit;

#[cfg(feature = "server")]
mod router;

#[cfg(feature = "server")]
pub use router::auth_router;

#[cfg(feature = "server")]
pub use session::{LoggedInData, UserSession, login};

#[cfg(feature = "web")]
pub mod webauthn_helpers;

#[cfg(any(feature = "web", feature = "server"))]
mod login_page;

#[cfg(any(feature = "web", feature = "server"))]
pub use login_page::LoginPage;
