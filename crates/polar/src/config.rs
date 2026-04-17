//! Configuration for Polar API client.

/// Configuration for the Polar API client.
///
/// This struct decouples Polar configuration from any application-specific
/// state, making it easier to test and reuse the client.
#[derive(Debug, Clone)]
pub struct PolarConfig {
    /// Polar API base URL (e.g., "https://api.polar.sh/v1")
    pub api_url: String,

    /// Polar API access token
    pub access_token: String,

    /// Base URL for redirect URLs (e.g., "https://yourapp.com")
    pub base_url: String,

    /// Product ID for Solo Monthly plan
    pub solo_monthly_product_id: String,

    /// Product ID for Solo Yearly plan
    pub solo_yearly_product_id: String,
}

impl PolarConfig {
    /// Create a new PolarConfig with default API URL.
    pub fn new(
        access_token: impl Into<String>,
        base_url: impl Into<String>,
        solo_monthly_product_id: impl Into<String>,
        solo_yearly_product_id: impl Into<String>,
    ) -> Self {
        Self {
            api_url: "https://api.polar.sh/v1".to_string(),
            access_token: access_token.into(),
            base_url: base_url.into(),
            solo_monthly_product_id: solo_monthly_product_id.into(),
            solo_yearly_product_id: solo_yearly_product_id.into(),
        }
    }

    /// Create a new PolarConfig with a custom API URL.
    pub fn with_api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = api_url.into();
        self
    }
}
