//! FerrisKey REST client for the dashboard's custom login UI.
//!
//! All state belonging to FerrisKey (the realm-scoped auth-flow session
//! identified by the `FERRISKEY_SESSION` cookie, plus any temporary token
//! returned mid-flow) lives server-side in our tower-sessions store. Browsers
//! never see those values — they only ever talk to our own `/auth/session/*`
//! endpoints.

mod client;
mod types;

pub use client::*;
pub use types::*;
