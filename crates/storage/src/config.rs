/// Configuration for S3-compatible storage
#[derive(Clone, Debug)]
pub struct S3Config {
    /// Custom endpoint URL (None for AWS S3, Some(url) for MinIO, DigitalOcean Spaces, Cloudflare R2, etc.)
    pub endpoint: Option<String>,
    /// AWS region (e.g., "us-east-1", "eu-west-1")
    pub region: String,
    /// S3 bucket name
    pub bucket: String,
    /// AWS access key ID
    pub access_key: String,
    /// AWS secret access key
    pub secret_key: String,
    /// Optional path prefix for all uploaded files (e.g., "screenshots/")
    pub path_prefix: Option<String>,
    /// Whether to use path-style addressing (required for some S3-compatible services like MinIO)
    pub force_path_style: bool,
}

impl S3Config {
    /// Create a new S3Config with required fields
    pub fn new(
        region: impl Into<String>,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: None,
            region: region.into(),
            bucket: bucket.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            path_prefix: None,
            force_path_style: false,
        }
    }

    /// Set custom endpoint for S3-compatible services
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set path prefix for all uploaded files
    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = Some(prefix.into());
        self
    }

    /// Enable path-style addressing (for MinIO and some other S3-compatible services)
    pub fn with_force_path_style(mut self, force: bool) -> Self {
        self.force_path_style = force;
        self
    }

    /// Get the full key path for a file, including the prefix
    pub fn full_key(&self, key: &str) -> String {
        match &self.path_prefix {
            Some(prefix) => {
                let prefix = prefix.trim_end_matches('/');
                format!("{}/{}", prefix, key)
            }
            None => key.to_string(),
        }
    }

    /// Get the public URL for an object
    /// For AWS S3, this returns the standard S3 URL
    /// For custom endpoints, this uses the endpoint URL
    pub fn public_url(&self, key: &str) -> String {
        let full_key = self.full_key(key);
        match &self.endpoint {
            Some(endpoint) => {
                let endpoint = endpoint.trim_end_matches('/');
                if self.force_path_style {
                    format!("{}/{}/{}", endpoint, self.bucket, full_key)
                } else {
                    // Virtual-hosted style
                    format!("{}/{}", endpoint, full_key)
                }
            }
            None => {
                // AWS S3 default URL format
                format!(
                    "https://{}.s3.{}.amazonaws.com/{}",
                    self.bucket, self.region, full_key
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_config() {
        let config = S3Config::new("us-east-1", "my-bucket", "access", "secret");
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.bucket, "my-bucket");
        assert!(config.endpoint.is_none());
        assert!(config.path_prefix.is_none());
        assert!(!config.force_path_style);
    }

    #[test]
    fn test_with_endpoint() {
        let config = S3Config::new("us-east-1", "my-bucket", "access", "secret")
            .with_endpoint("http://localhost:9000");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
    }

    #[test]
    fn test_full_key_without_prefix() {
        let config = S3Config::new("us-east-1", "my-bucket", "access", "secret");
        assert_eq!(config.full_key("test.jpg"), "test.jpg");
    }

    #[test]
    fn test_full_key_with_prefix() {
        let config = S3Config::new("us-east-1", "my-bucket", "access", "secret")
            .with_path_prefix("screenshots/");
        assert_eq!(config.full_key("test.jpg"), "screenshots/test.jpg");
    }

    #[test]
    fn test_public_url_aws() {
        let config = S3Config::new("us-east-1", "my-bucket", "access", "secret");
        let url = config.public_url("test.jpg");
        assert_eq!(url, "https://my-bucket.s3.us-east-1.amazonaws.com/test.jpg");
    }

    #[test]
    fn test_public_url_custom_endpoint_path_style() {
        let config = S3Config::new("us-east-1", "my-bucket", "access", "secret")
            .with_endpoint("http://localhost:9000")
            .with_force_path_style(true);
        let url = config.public_url("test.jpg");
        assert_eq!(url, "http://localhost:9000/my-bucket/test.jpg");
    }
}
