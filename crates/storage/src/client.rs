use s3::creds::Credentials as S3Credentials;
use s3::{Bucket, Region};

use crate::config::S3Config;
use crate::error::{Result, StorageError};

/// Wrapper around the rust-s3 Bucket with custom configuration
#[derive(Clone)]
pub struct StorageClient {
    bucket: Box<Bucket>,
    config: S3Config,
}

impl StorageClient {
    /// Create a new StorageClient with the given configuration
    pub async fn new(config: S3Config) -> Result<Self> {
        let bucket = Self::create_bucket(&config)?;
        Ok(Self { bucket, config })
    }

    /// Get a reference to the underlying Bucket
    pub(crate) fn bucket(&self) -> &Bucket {
        &self.bucket
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &S3Config {
        &self.config
    }

    /// Get the bucket name
    pub fn bucket_name(&self) -> &str {
        &self.config.bucket
    }

    /// Create the rust-s3 Bucket with custom configuration
    fn create_bucket(config: &S3Config) -> Result<Box<Bucket>> {
        let credentials = S3Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )
        .map_err(|e| StorageError::InitializationFailed(e.to_string()))?;

        let region = match &config.endpoint {
            Some(endpoint) => Region::Custom {
                region: config.region.clone(),
                endpoint: endpoint.clone(),
            },
            None => config
                .region
                .parse::<Region>()
                .map_err(|e| StorageError::InitializationFailed(e.to_string()))?,
        };

        let mut bucket = Bucket::new(&config.bucket, region, credentials)
            .map_err(|e| StorageError::InitializationFailed(e.to_string()))?;

        if config.force_path_style {
            bucket = bucket.with_path_style();
        }

        tracing::info!(
            "S3 storage client initialized for bucket '{}' in region '{}'",
            config.bucket,
            config.region
        );

        Ok(bucket)
    }

    /// Verify the storage connection by checking if the bucket exists
    pub async fn verify_connection(&self) -> Result<()> {
        self.bucket.location().await.map_err(|e| {
            StorageError::InitializationFailed(format!(
                "Failed to access bucket '{}': {}",
                self.config.bucket, e
            ))
        })?;

        tracing::info!(
            "Successfully verified access to bucket '{}'",
            self.config.bucket
        );
        Ok(())
    }
}

impl std::fmt::Debug for StorageClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageClient")
            .field("bucket", &self.config.bucket)
            .field("region", &self.config.region)
            .field("endpoint", &self.config.endpoint)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = S3Config::new("us-east-1", "test-bucket", "access-key", "secret-key");

        let result = StorageClient::new(config).await;
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.bucket_name(), "test-bucket");
    }

    #[tokio::test]
    async fn test_client_with_custom_endpoint() {
        let config = S3Config::new("us-east-1", "test-bucket", "access-key", "secret-key")
            .with_endpoint("http://localhost:9000")
            .with_force_path_style(true);

        let result = StorageClient::new(config).await;
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(
            client.config().endpoint,
            Some("http://localhost:9000".to_string())
        );
        assert!(client.config().force_path_style);
    }
}
