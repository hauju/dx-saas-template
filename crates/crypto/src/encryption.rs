//! AES-256-GCM encryption for sensitive data at rest.
//!
//! This module provides functions to encrypt and decrypt secrets (like webhook secrets)
//! using AES-256-GCM, which provides both confidentiality and authenticity.
//!
//! # Format
//!
//! Encrypted values are stored as base64-encoded strings in the format:
//! `base64(nonce || ciphertext || tag)`
//!
//! - nonce: 12 bytes (96 bits)
//! - ciphertext: variable length (same as plaintext)
//! - tag: 16 bytes (128 bits)
//!
//! # Security Considerations
//!
//! - The encryption key must be exactly 32 bytes (256 bits)
//! - A unique random nonce is generated for each encryption
//! - The nonce is stored with the ciphertext (it doesn't need to be secret)
//! - Never reuse a nonce with the same key

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use base64::Engine;

use crate::{Error, Result};

/// Length of the AES-256 key in bytes
pub const KEY_LENGTH: usize = 32;

/// Length of the GCM nonce in bytes
pub const NONCE_LENGTH: usize = 12;

/// Encrypt a plaintext secret using AES-256-GCM.
///
/// # Arguments
///
/// * `plaintext` - The secret to encrypt
/// * `key` - A 32-byte encryption key
///
/// # Returns
///
/// A base64-encoded string containing nonce + ciphertext + tag.
///
/// # Errors
///
/// Returns an error if encryption fails or the key is invalid.
///
/// # Example
///
/// ```
/// use crypto::encryption::{encrypt_secret, KEY_LENGTH};
///
/// let key = [0u8; KEY_LENGTH]; // In practice, use a secure random key
/// let encrypted = encrypt_secret("my-webhook-secret", &key).unwrap();
/// assert!(!encrypted.is_empty());
/// ```
pub fn encrypt_secret(plaintext: &str, key: &[u8; KEY_LENGTH]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::EncryptionFailed(format!("Failed to create cipher: {}", e)))?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| Error::EncryptionFailed(format!("Encryption failed: {}", e)))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt a secret that was encrypted with `encrypt_secret`.
///
/// # Arguments
///
/// * `encrypted` - The base64-encoded encrypted string
/// * `key` - The same 32-byte key used for encryption
///
/// # Returns
///
/// The original plaintext secret.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted string is not valid base64
/// - The encrypted data is too short (missing nonce)
/// - The key is incorrect
/// - The ciphertext has been tampered with
///
/// # Example
///
/// ```
/// use crypto::encryption::{encrypt_secret, decrypt_secret, KEY_LENGTH};
///
/// let key = [0u8; KEY_LENGTH]; // In practice, use a secure random key
/// let encrypted = encrypt_secret("my-webhook-secret", &key).unwrap();
/// let decrypted = decrypt_secret(&encrypted, &key).unwrap();
/// assert_eq!(decrypted, "my-webhook-secret");
/// ```
pub fn decrypt_secret(encrypted: &str, key: &[u8; KEY_LENGTH]) -> Result<String> {
    // Decode from base64
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| Error::DecryptionFailed(format!("Invalid base64: {}", e)))?;

    // Ensure we have at least nonce + some ciphertext
    if combined.len() < NONCE_LENGTH + 1 {
        return Err(Error::DecryptionFailed(
            "Encrypted data too short".to_string(),
        ));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LENGTH);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Create cipher and decrypt
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::DecryptionFailed(format!("Failed to create cipher: {}", e)))?;

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        Error::DecryptionFailed(format!(
            "Decryption failed (wrong key or tampered data): {}",
            e
        ))
    })?;

    String::from_utf8(plaintext)
        .map_err(|e| Error::DecryptionFailed(format!("Invalid UTF-8 in decrypted data: {}", e)))
}

/// Parse an encryption key from a base64-encoded string.
///
/// # Arguments
///
/// * `key_base64` - A base64-encoded 32-byte key
///
/// # Returns
///
/// A 32-byte key array suitable for use with `encrypt_secret` and `decrypt_secret`.
///
/// # Errors
///
/// Returns an error if:
/// - The string is not valid base64
/// - The decoded key is not exactly 32 bytes
///
/// # Example
///
/// ```
/// use crypto::encryption::parse_key;
///
/// // A 32-byte key encoded as base64
/// let key_base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// let key = parse_key(key_base64).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn parse_key(key_base64: &str) -> Result<[u8; KEY_LENGTH]> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_base64.trim())
        .map_err(|e| Error::InvalidKey(format!("Invalid base64: {}", e)))?;

    if key_bytes.len() != KEY_LENGTH {
        return Err(Error::InvalidKey(format!(
            "Key must be exactly {} bytes, got {}",
            KEY_LENGTH,
            key_bytes.len()
        )));
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Generate a new random encryption key.
///
/// This generates a cryptographically secure 32-byte key suitable for AES-256-GCM.
///
/// # Returns
///
/// A 32-byte random key.
///
/// # Example
///
/// ```
/// use crypto::encryption::generate_key;
///
/// let key = generate_key();
/// assert_eq!(key.len(), 32);
/// ```
pub fn generate_key() -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encode an encryption key as base64 for storage.
///
/// # Arguments
///
/// * `key` - A 32-byte encryption key
///
/// # Returns
///
/// A base64-encoded string representation of the key.
///
/// # Example
///
/// ```
/// use crypto::encryption::{generate_key, encode_key};
///
/// let key = generate_key();
/// let encoded = encode_key(&key);
/// println!("Store this key securely: {}", encoded);
/// ```
pub fn encode_key(key: &[u8; KEY_LENGTH]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = "whsec_abcdef123456";

        let encrypted = encrypt_secret(plaintext, &key).unwrap();
        let decrypted = decrypt_secret(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_different_each_time() {
        let key = generate_key();
        let plaintext = "same-secret";

        let encrypted1 = encrypt_secret(plaintext, &key).unwrap();
        let encrypted2 = encrypt_secret(plaintext, &key).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(decrypt_secret(&encrypted1, &key).unwrap(), plaintext);
        assert_eq!(decrypt_secret(&encrypted2, &key).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = "secret";

        let encrypted = encrypt_secret(plaintext, &key1).unwrap();
        let result = decrypt_secret(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = generate_key();
        let plaintext = "secret";

        let encrypted = encrypt_secret(plaintext, &key).unwrap();

        // Tamper with the encrypted data
        let mut tampered = base64::engine::general_purpose::STANDARD
            .decode(&encrypted)
            .unwrap();
        if let Some(byte) = tampered.last_mut() {
            *byte ^= 0xFF;
        }
        let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(&tampered);

        let result = decrypt_secret(&tampered_b64, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base64_fails() {
        let key = generate_key();
        let result = decrypt_secret("not-valid-base64!!!", &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_short_data_fails() {
        let key = generate_key();
        // Only 5 bytes, less than nonce length
        let short = base64::engine::general_purpose::STANDARD.encode([1, 2, 3, 4, 5]);
        let result = decrypt_secret(&short, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_key_valid() {
        let original_key = generate_key();
        let encoded = encode_key(&original_key);
        let parsed = parse_key(&encoded).unwrap();
        assert_eq!(parsed, original_key);
    }

    #[test]
    fn test_parse_key_wrong_length() {
        // 16 bytes instead of 32
        let short_key = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let result = parse_key(&short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = generate_key();
        let encrypted = encrypt_secret("", &key).unwrap();
        let decrypted = decrypt_secret(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_unicode_plaintext() {
        let key = generate_key();
        let plaintext = "webhook-secret-\u{1F512}-\u{1F511}"; // with lock and key emojis

        let encrypted = encrypt_secret(plaintext, &key).unwrap();
        let decrypted = decrypt_secret(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
