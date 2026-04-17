//! Secure secret hashing with Argon2
//!
//! Argon2 is the winner of the Password Hashing Competition and is recommended
//! for hashing secrets like passwords and API keys. It's designed to be:
//! - Memory-hard (resistant to GPU/ASIC attacks)
//! - Configurable (time, memory, parallelism parameters)
//! - Side-channel resistant

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::rngs::OsRng;

use crate::{Error, Result};

/// Hash a secret using Argon2 with default parameters.
///
/// Generates a random salt and returns a PHC-formatted hash string
/// that includes the salt and parameters for later verification.
///
/// # Arguments
/// * `secret` - The secret string to hash (e.g., password, API key)
///
/// # Returns
/// A PHC-formatted hash string containing algorithm, parameters, salt, and hash
///
/// # Errors
/// Returns an error if hashing fails
///
/// # Example
/// ```
/// use crypto::hash_secret;
///
/// let hash = hash_secret("my_secret_key").unwrap();
/// assert!(hash.starts_with("$argon2"));
/// ```
pub fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| Error::HashingFailed(e.to_string()))?
        .to_string();
    Ok(hash)
}

/// Verify a secret against a stored Argon2 hash.
///
/// Parses the PHC-formatted hash string and uses constant-time comparison
/// to verify the secret matches.
///
/// # Arguments
/// * `hash` - The PHC-formatted hash string (from `hash_secret`)
/// * `secret` - The secret to verify
///
/// # Returns
/// `true` if the secret matches the hash, `false` otherwise
///
/// # Note
/// This function returns `false` for invalid hash formats rather than
/// propagating errors, making it safe to use in authentication flows.
pub fn verify_secret(hash: &str, secret: &str) -> bool {
    let argon2 = Argon2::default();
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    argon2
        .verify_password(secret.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_secret_format() {
        let hash = hash_secret("test_secret").unwrap();
        assert!(hash.starts_with("$argon2"), "Hash should be Argon2 format");
    }

    #[test]
    fn test_hash_secret_uniqueness() {
        let hash1 = hash_secret("same_secret").unwrap();
        let hash2 = hash_secret("same_secret").unwrap();
        assert_ne!(
            hash1, hash2,
            "Same secret should produce different hashes due to random salt"
        );
    }

    #[test]
    fn test_verify_secret_correct() {
        let secret = "my_api_key_123";
        let hash = hash_secret(secret).unwrap();
        assert!(verify_secret(&hash, secret), "Should verify correct secret");
    }

    #[test]
    fn test_verify_secret_incorrect() {
        let hash = hash_secret("correct_secret").unwrap();
        assert!(
            !verify_secret(&hash, "wrong_secret"),
            "Should reject incorrect secret"
        );
    }

    #[test]
    fn test_verify_secret_invalid_hash() {
        assert!(!verify_secret("invalid_hash_string", "any_secret"));
        assert!(!verify_secret("", "any_secret"));
    }
}
