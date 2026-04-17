//! Error types for Polar API operations.

use thiserror::Error;

/// Error type for Polar API operations.
#[derive(Debug, Error)]
pub enum PolarError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// API returned an error response
    #[error("Polar API error: status={status}, message={message}")]
    Api {
        /// HTTP status code
        status: u16,
        /// Error message from API
        message: String,
    },

    /// Invalid webhook signature
    #[error("Invalid webhook signature: {0}")]
    InvalidSignature(String),

    /// Missing required webhook headers
    #[error("Missing required webhook headers: {0}")]
    MissingWebhookHeaders(String),

    /// Failed to parse response
    #[error("Failed to parse response: {0}")]
    Parse(#[from] serde_json::Error),

    /// Validation error (e.g., invalid plan ID)
    #[error("Validation error: {0}")]
    Validation(String),

    /// Webhook verification library error
    #[error("Webhook verification failed: {0}")]
    WebhookVerification(String),
}

/// Result type for Polar operations.
pub type PolarResult<T> = Result<T, PolarError>;
