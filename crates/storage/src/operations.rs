use chrono::{DateTime, Utc};
use http::HeaderMap;
use http::header::CONTENT_DISPOSITION;
use serde::{Deserialize, Serialize};

use crate::client::StorageClient;
use crate::error::{Result, StorageError};

/// Maximum file size allowed for uploads (10 MB)
pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Allowed content types for screenshot uploads
pub const ALLOWED_CONTENT_TYPES: &[&str] = &["image/jpeg", "image/png", "image/webp"];

/// Result of a successful upload operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    /// The S3 object key (path within the bucket)
    pub key: String,
    /// The public URL to access the file
    pub url: String,
    /// Size of the uploaded file in bytes
    pub size_bytes: usize,
    /// Content type of the uploaded file
    pub content_type: String,
    /// Original filename
    pub filename: String,
    /// Timestamp when the file was uploaded
    pub uploaded_at: DateTime<Utc>,
}

impl StorageClient {
    /// Upload a file to S3
    ///
    /// # Arguments
    /// * `bytes` - The file content as bytes
    /// * `content_type` - MIME type of the file (e.g., "image/jpeg")
    /// * `filename` - Original filename (used for Content-Disposition)
    ///
    /// # Returns
    /// * `UploadResult` with the key, URL, and metadata
    ///
    /// # Errors
    /// * `StorageError::FileTooLarge` if the file exceeds MAX_FILE_SIZE
    /// * `StorageError::UnsupportedContentType` if the content type is not allowed
    /// * `StorageError::UploadFailed` if the S3 upload fails
    pub async fn upload_file(
        &self,
        bytes: Vec<u8>,
        content_type: &str,
        filename: &str,
    ) -> Result<UploadResult> {
        // Validate file size
        let size_bytes = bytes.len();
        if size_bytes > MAX_FILE_SIZE {
            return Err(StorageError::FileTooLarge {
                size_bytes,
                max_bytes: MAX_FILE_SIZE,
            });
        }

        // Validate content type
        if !ALLOWED_CONTENT_TYPES.contains(&content_type) {
            return Err(StorageError::UnsupportedContentType(
                content_type.to_string(),
            ));
        }

        // Generate a unique key for the file
        let extension = mime_guess::get_mime_extensions_str(content_type)
            .and_then(|exts| exts.first())
            .unwrap_or(&"bin");
        let uuid = uuid::Uuid::new_v4();
        let key = format!("{}.{}", uuid, extension);
        let full_key = self.config().full_key(&key);

        let uploaded_at = Utc::now();

        // Set Content-Disposition header
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_DISPOSITION,
            format!("inline; filename=\"{}\"", sanitize_filename(filename))
                .parse()
                .map_err(|e| StorageError::UploadFailed(format!("Invalid header value: {}", e)))?,
        );
        let upload_bucket = self
            .bucket()
            .with_extra_headers(headers)
            .map_err(|e| StorageError::UploadFailed(e.to_string()))?;

        // Upload to S3
        let response = upload_bucket
            .put_object_with_content_type(&full_key, &bytes, content_type)
            .await
            .map_err(|e| StorageError::UploadFailed(format!("S3 PutObject failed: {}", e)))?;

        if response.status_code() != 200 {
            return Err(StorageError::UploadFailed(format!(
                "S3 PutObject returned status {}",
                response.status_code()
            )));
        }

        let url = self.config().public_url(&key);

        tracing::info!(
            key = %full_key,
            size_bytes = size_bytes,
            content_type = %content_type,
            "Successfully uploaded file to S3"
        );

        Ok(UploadResult {
            key: full_key,
            url,
            size_bytes,
            content_type: content_type.to_string(),
            filename: filename.to_string(),
            uploaded_at,
        })
    }

    /// Delete a file from S3
    ///
    /// # Arguments
    /// * `key` - The S3 object key to delete
    ///
    /// # Errors
    /// * `StorageError::DeleteFailed` if the S3 delete fails
    pub async fn delete_file(&self, key: &str) -> Result<()> {
        self.bucket()
            .delete_object(key)
            .await
            .map_err(|e| StorageError::DeleteFailed(format!("S3 DeleteObject failed: {}", e)))?;

        tracing::info!(key = %key, "Successfully deleted file from S3");

        Ok(())
    }

    /// Generate a presigned URL for temporary access to a file
    ///
    /// # Arguments
    /// * `key` - The S3 object key
    /// * `expiry_secs` - How long the URL should be valid (in seconds)
    ///
    /// # Returns
    /// * A presigned URL string
    ///
    /// # Errors
    /// * `StorageError::PresignFailed` if URL generation fails
    pub async fn generate_presigned_url(&self, key: &str, expiry_secs: u64) -> Result<String> {
        let expiry = u32::try_from(expiry_secs).map_err(|_| {
            StorageError::PresignFailed(format!(
                "Expiry duration {} seconds exceeds maximum",
                expiry_secs
            ))
        })?;

        let url = self
            .bucket()
            .presign_get(key, expiry, None)
            .await
            .map_err(|e| StorageError::PresignFailed(format!("Presign request failed: {}", e)))?;

        tracing::debug!(
            key = %key,
            expiry_secs = expiry_secs,
            "Generated presigned URL for S3 object"
        );

        Ok(url)
    }

    /// Check if a file exists in S3
    ///
    /// # Arguments
    /// * `key` - The S3 object key to check
    ///
    /// # Returns
    /// * `true` if the file exists, `false` otherwise
    pub async fn file_exists(&self, key: &str) -> bool {
        self.bucket().head_object(key).await.is_ok()
    }
}

/// Sanitize a filename for use in Content-Disposition header
fn sanitize_filename(filename: &str) -> String {
    // Remove or replace problematic characters
    filename
        .chars()
        .map(|c| match c {
            '"' | '\\' | '/' | ':' | '*' | '?' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test.jpg"), "test.jpg");
        assert_eq!(sanitize_filename("test\"file.jpg"), "test_file.jpg");
        assert_eq!(sanitize_filename("path/to/file.jpg"), "path_to_file.jpg");
        assert_eq!(sanitize_filename("file:name.jpg"), "file_name.jpg");
    }

    #[test]
    fn test_allowed_content_types() {
        assert!(ALLOWED_CONTENT_TYPES.contains(&"image/jpeg"));
        assert!(ALLOWED_CONTENT_TYPES.contains(&"image/png"));
        assert!(ALLOWED_CONTENT_TYPES.contains(&"image/webp"));
        assert!(!ALLOWED_CONTENT_TYPES.contains(&"text/plain"));
    }
}
