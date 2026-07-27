//! Authentication crate.
//!
//! Drives a custom login UI against FerrisKey's REST API. Owns OIDC code
//! exchange, password / passkey verification, and our own email-OTP fallback.
//!
//! The application provides trait implementations via `AuthUserStore`
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
pub use traits::{AuthEmailSender, AuthRateLimitStore, AuthUserStore};

#[cfg(feature = "server")]
pub mod jwt;

#[cfg(feature = "server")]
pub use jwt::JwksCache;

#[cfg(feature = "server")]
pub mod ferriskey;

#[cfg(feature = "server")]
pub mod session;

#[cfg(feature = "server")]
pub mod handlers;

#[cfg(feature = "server")]
pub mod csrf;

#[cfg(feature = "server")]
pub mod rate_limit;
#[cfg(feature = "server")]
pub use rate_limit::AUTH_REQUESTS_PER_MINUTE;

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
