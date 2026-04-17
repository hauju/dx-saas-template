//! Error types for cryptographic operations

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to generate random bytes from the OS random number generator
    #[error("Failed to generate random bytes: {0}")]
    RandomGenerationFailed(String),

    /// Failed to hash a secret using Argon2
    #[error("Failed to hash secret: {0}")]
    HashingFailed(String),

    /// Failed to parse a password hash
    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    /// Failed to encrypt data
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Failed to decrypt data
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid encryption key
    #[error("Invalid encryption key: {0}")]
    InvalidKey(String),
}
