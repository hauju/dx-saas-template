//! Zitadel Session API v2 + User API v2 client using the official `zitadel` crate (gRPC).
//!
//! Public function signatures are preserved so handler call sites remain unchanged.
//! Internally, each function builds a gRPC client and calls the corresponding service method.

mod client;
mod types;

pub use client::*;
pub use types::*;
