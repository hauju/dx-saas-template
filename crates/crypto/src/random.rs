//! Secure random byte generation
//!
//! All random generation in this module uses `OsRng`, which is backed by the operating
//! system's cryptographically secure random number generator. This is the recommended
//! source of randomness for security-critical operations.

use base64::Engine as _;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::{Error, Result};

/// Generate cryptographically secure random bytes.
///
/// Uses `OsRng` to ensure proper entropy from the operating system.
///
/// # Arguments
/// * `length` - Number of random bytes to generate
///
/// # Returns
/// A vector of random bytes
///
/// # Errors
/// Returns an error if the OS random number generator fails
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| Error::RandomGenerationFailed(e.to_string()))?;
    Ok(bytes)
}

/// Generate a URL-safe base64-encoded token from random bytes.
///
/// The output length will be approximately 4/3 of the input byte count
/// (base64 encoding expands the data).
///
/// # Arguments
/// * `byte_length` - Number of random bytes to use (default: 32 for 256-bit security)
///
/// # Returns
/// A URL-safe base64-encoded string (no padding)
///
/// # Errors
/// Returns an error if random byte generation fails
pub fn generate_url_safe_token(byte_length: usize) -> Result<String> {
    let bytes = generate_random_bytes(byte_length)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Generate a cryptographically secure numeric OTP of the given length.
///
/// Uses `OsRng` to ensure each digit is uniformly distributed (0–9).
///
/// # Arguments
/// * `length` - Number of digits in the OTP (e.g., 6 for a 6-digit code)
///
/// # Returns
/// A string of exactly `length` decimal digits
///
/// # Errors
/// Returns an error if the OS random number generator fails
pub fn generate_numeric_otp(length: usize) -> Result<String> {
    use rand::Rng;
    let mut rng = OsRng;
    let code: String = (0..length)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect();
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes_length() {
        let bytes = generate_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        let bytes = generate_random_bytes(64).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn test_generate_random_bytes_uniqueness() {
        let bytes1 = generate_random_bytes(32).unwrap();
        let bytes2 = generate_random_bytes(32).unwrap();
        assert_ne!(bytes1, bytes2, "Random bytes should be unique");
    }

    #[test]
    fn test_generate_url_safe_token() {
        let token = generate_url_safe_token(32).unwrap();
        // 32 bytes encoded as base64 (no padding) = 43 characters
        assert_eq!(token.len(), 43);

        // Verify it's valid base64
        assert!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&token)
                .is_ok()
        );
    }

    #[test]
    fn test_generate_url_safe_token_uniqueness() {
        let token1 = generate_url_safe_token(32).unwrap();
        let token2 = generate_url_safe_token(32).unwrap();
        assert_ne!(token1, token2, "Tokens should be unique");
    }
}
