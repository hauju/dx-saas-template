//! Polar API client and webhook handling.
//!
//! This crate provides a decoupled Polar API client with:
//! - Customer management (create, lookup, list)
//! - Subscription management (create trials, list, check history)
//! - Checkout session creation (redirect-based)
//! - Webhook signature verification
//!
//! # Example
//!
//! ```rust,ignore
//! use polar::{PolarClient, PolarConfig};
//!
//! let config = PolarConfig::new(
//!     "your-token",
//!     "https://yourapp.com",
//!     "prod_solo_monthly",
//!     "prod_solo_yearly",
//! );
//!
//! let client = PolarClient::new(config);
//! let customer = client.get_customer_by_email("user@example.com").await?;
//! ```

mod client;
mod config;
mod error;
mod types;
mod webhook;

pub use client::PolarClient;
pub use config::PolarConfig;
pub use error::{PolarError, PolarResult};
pub use types::*;
pub use webhook::{normalize_polar_webhook_secret, verify_webhook};
