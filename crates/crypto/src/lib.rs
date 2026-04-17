//! Cryptographic Utilities
//!
//! This crate provides secure cryptographic primitives for the SeggWat application:
//!
//! - **random**: Secure random byte generation using OS-level entropy
//! - **hashing**: Password/secret hashing with Argon2
//! - **tokens**: Token generation utilities for API keys, invitations, and CSRF protection
//! - **encryption**: AES-256-GCM encryption for secrets at rest

pub mod encryption;
mod error;
mod hashing;
mod random;
mod tokens;

pub use error::{Error, Result};
pub use hashing::{hash_secret, verify_secret};
pub use random::{generate_numeric_otp, generate_random_bytes, generate_url_safe_token};
pub use tokens::{generate_api_key, generate_csrf_token, generate_invitation_token};
