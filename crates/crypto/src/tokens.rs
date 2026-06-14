//! Token generation utilities
//!
//! Provides high-level functions for generating various types of tokens
//! used throughout the application:
//!
//! - **API keys**: Prefixed tokens for API authentication
//! - **Invitation tokens**: URL-safe tokens for email invitations
//! - **CSRF tokens**: Protection against cross-site request forgery

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::{Result, random::generate_url_safe_token};

/// Default token length in bytes (256-bit security)
const DEFAULT_TOKEN_BYTES: usize = 32;

/// Number of leading characters of an API key stored, unhashed, for indexed lookup.
///
/// Covers the `oat_` prefix plus 8 random characters (~48 bits) — enough to make
/// the lookup selective while the full 256-bit secret stays Argon2-hashed.
pub const API_KEY_PREFIX_LEN: usize = 12;

/// Derive the indexed lookup prefix from a presented API key.
///
/// Returns `None` for anything that isn't a well-formed `oat_` token, so callers
/// can reject malformed credentials before touching the database.
///
/// # Example
/// ```
/// use crypto::{generate_api_key, api_key_prefix};
///
/// let key = generate_api_key().unwrap();
/// let prefix = api_key_prefix(&key).unwrap();
/// assert!(key.starts_with(&prefix));
/// assert_eq!(prefix.len(), 12);
/// ```
pub fn api_key_prefix(token: &str) -> Option<String> {
    if !token.starts_with("oat_") || token.len() < API_KEY_PREFIX_LEN {
        return None;
    }
    // API keys are URL-safe base64 (ASCII), so byte-slicing on a char boundary is safe.
    Some(token[..API_KEY_PREFIX_LEN].to_string())
}

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

/// Verify a PKCE `code_verifier` against an `S256` `code_challenge` (RFC 7636).
///
/// Computes `BASE64URL-NO-PAD(SHA256(code_verifier))` and compares it to the
/// stored challenge. Only the `S256` method is supported (plain PKCE is rejected
/// elsewhere).
///
/// # Example
/// ```
/// use crypto::pkce_s256_matches;
///
/// // RFC 7636 Appendix B test vector
/// let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// assert!(pkce_s256_matches(verifier, challenge));
/// ```
pub fn pkce_s256_matches(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == code_challenge
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

    #[test]
    fn test_api_key_prefix_roundtrip() {
        let key = generate_api_key().unwrap();
        let prefix = api_key_prefix(&key).unwrap();
        assert_eq!(prefix.len(), API_KEY_PREFIX_LEN);
        assert!(key.starts_with(&prefix));
        assert!(prefix.starts_with("oat_"));
    }

    #[test]
    fn test_api_key_prefix_rejects_malformed() {
        assert!(api_key_prefix("not-an-oat-key").is_none());
        assert!(api_key_prefix("oat_short").is_none());
        assert!(api_key_prefix("").is_none());
    }

    #[test]
    fn test_pkce_s256_rfc7636_vector() {
        // RFC 7636 Appendix B
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_s256_matches(verifier, challenge));
    }

    #[test]
    fn test_pkce_s256_rejects_mismatch() {
        assert!(!pkce_s256_matches(
            "wrong-verifier",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_s256_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "tampered"
        ));
    }
}
