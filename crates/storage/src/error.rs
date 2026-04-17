use thiserror::Error;

/// Storage-specific errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("S3 client initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Upload failed: {0}")]
    UploadFailed(String),

    #[error("Delete failed: {0}")]
    DeleteFailed(String),

    #[error("Presigned URL generation failed: {0}")]
    PresignFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("File too large: {size_bytes} bytes exceeds maximum {max_bytes} bytes")]
    FileTooLarge { size_bytes: usize, max_bytes: usize },

    #[error("Unsupported content type: {0}")]
    UnsupportedContentType(String),
}

/// Result type alias for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;
