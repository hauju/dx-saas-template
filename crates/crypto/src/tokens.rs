//! Token generation utilities
//!
//! Provides high-level functions for generating various types of tokens
//! used throughout the application:
//!
//! - **API keys**: Prefixed tokens for API authentication
//! - **Invitation tokens**: URL-safe tokens for email invitations
//! - **CSRF tokens**: Protection against cross-site request forgery

use crate::{Result, random::generate_url_safe_token};

/// Default token length in bytes (256-bit security)
const DEFAULT_TOKEN_BYTES: usize = 32;

/// Generate an API key with the format "oat_<random-url-safe-43chars>".
///
/// The prefix makes it easy to identify and rotate API keys in logs,
/// while the random portion provides 256 bits of entropy.
///
/// # Returns
/// An API key string like `oat_AbCdEf123...` (47 characters total)
///
/// # Errors
/// Returns an error if random byte generation fails
///
/// # Example
/// ```
/// use crypto::generate_api_key;
///
/// let key = generate_api_key().unwrap();
/// assert!(key.starts_with("oat_"));
/// assert_eq!(key.len(), 47); // "oat_" (4) + base64(32 bytes) (43)
/// ```
pub fn generate_api_key() -> Result<String> {
    let token = generate_url_safe_token(DEFAULT_TOKEN_BYTES)?;
    Ok(format!("oat_{}", token))
}

/// Generate a secure invitation token for email-based invitations.
///
/// Returns a URL-safe base64-encoded token suitable for embedding
/// in invitation links.
///
/// # Returns
/// A 43-character URL-safe token string
///
/// # Errors
/// Returns an error if random byte generation fails
///
/// # Example
/// ```
/// use crypto::generate_invitation_token;
///
/// let token = generate_invitation_token().unwrap();
/// let invite_url = format!("https://example.com/invite?token={}", token);
/// ```
pub fn generate_invitation_token() -> Result<String> {
    generate_url_safe_token(DEFAULT_TOKEN_BYTES)
}

/// Generate a CSRF token for OAuth state parameter protection.
///
/// Used to prevent cross-site request forgery in OAuth flows by
/// ensuring the callback came from our original redirect.
///
/// # Returns
/// A 43-character URL-safe token string
///
/// # Errors
/// Returns an error if random byte generation fails
///
/// # Example
/// ```
/// use crypto::generate_csrf_token;
///
/// let state = generate_csrf_token().unwrap();
/// // Store in session, then include in OAuth redirect URL
/// let auth_url = format!("https://auth.example.com/authorize?state={}", state);
/// ```
pub fn generate_csrf_token() -> Result<String> {
    generate_url_safe_token(DEFAULT_TOKEN_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_format() {
        let key = generate_api_key().unwrap();
        assert!(key.starts_with("oat_"), "API key should have oat_ prefix");
        assert_eq!(
            key.len(),
            47,
            "API key should be 47 characters (4 prefix + 43 base64)"
        );
    }

    #[test]
    fn test_generate_api_key_uniqueness() {
        let key1 = generate_api_key().unwrap();
        let key2 = generate_api_key().unwrap();
        assert_ne!(key1, key2, "API keys should be unique");
    }

    #[test]
    fn test_generate_invitation_token_length() {
        let token = generate_invitation_token().unwrap();
        assert_eq!(token.len(), 43, "Token should be 43 characters");
    }

    #[test]
    fn test_generate_invitation_token_url_safe() {
        let token = generate_invitation_token().unwrap();
        // URL-safe base64 only contains alphanumeric, -, and _
        assert!(
            token
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "Token should be URL-safe"
        );
    }

    #[test]
    fn test_generate_csrf_token_length() {
        let token = generate_csrf_token().unwrap();
        assert_eq!(token.len(), 43, "CSRF token should be 43 characters");
    }

    #[test]
    fn test_generate_csrf_token_uniqueness() {
        let token1 = generate_csrf_token().unwrap();
        let token2 = generate_csrf_token().unwrap();
        assert_ne!(token1, token2, "CSRF tokens should be unique");
    }
}
