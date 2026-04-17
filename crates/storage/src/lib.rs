//! S3-compatible storage abstraction for SeggWat
//!
//! This crate provides a unified interface for uploading, downloading, and managing
//! files in S3-compatible storage services including:
//!
//! - AWS S3
//! - MinIO
//! - DigitalOcean Spaces
//! - Cloudflare R2
//! - Any other S3-compatible service
//!
//! # Example
//!
//! ```rust,no_run
//! use storage::{StorageClient, S3Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create configuration for AWS S3
//!     let config = S3Config::new(
//!         "us-east-1",
//!         "my-bucket",
//!         "AKIAIOSFODNN7EXAMPLE",
//!         "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//!     )
//!     .with_path_prefix("screenshots/");
//!
//!     // Create the storage client
//!     let client = StorageClient::new(config).await?;
//!
//!     // Upload a file
//!     let bytes = std::fs::read("screenshot.jpg")?;
//!     let result = client.upload_file(bytes, "image/jpeg", "screenshot.jpg").await?;
//!
//!     println!("Uploaded to: {}", result.url);
//!     Ok(())
//! }
//! ```
//!
//! # Using with MinIO or other S3-compatible services
//!
//! ```rust,no_run
//! use storage::{StorageClient, S3Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = S3Config::new("us-east-1", "my-bucket", "minioadmin", "minioadmin")
//!         .with_endpoint("http://localhost:9000")
//!         .with_force_path_style(true)
//!         .with_path_prefix("uploads/");
//!
//!     let client = StorageClient::new(config).await?;
//!     Ok(())
//! }
//! ```

mod client;
mod config;
mod error;
mod operations;

// Re-export public types
pub use client::StorageClient;
pub use config::S3Config;
pub use error::{Result, StorageError};
pub use operations::{ALLOWED_CONTENT_TYPES, MAX_FILE_SIZE, UploadResult};
