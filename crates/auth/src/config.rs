/// Configuration for auth routes, redirects, and Zitadel integration.
///
/// Replaces all reads from `AppState.config.*` and `AppState.secrets.*`
/// that the auth crate previously needed.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// URL for the login page (e.g. "/login")
    pub login_page_url: String,
    /// Default redirect after login (e.g. "/org/redirect" or "/dashboard")
    pub default_post_login_url: String,

    // ── Zitadel configuration ──────────────────────────────────────
    /// Zitadel domain (e.g. "auth.example.com" or "localhost:8085")
    pub zitadel_domain: String,
    /// Zitadel organization ID (optional, scopes login to specific org)
    pub zitadel_org_id: Option<String>,
    /// Zitadel service user personal access token (for Session API v2)
    pub zitadel_service_user_token: Option<String>,

    // ── Application URLs ───────────────────────────────────────────
    /// Base URL where the dashboard is deployed (e.g. "https://seggwat.com")
    pub base_url: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            login_page_url: "/login".to_string(),
            default_post_login_url: "/dashboard".to_string(),
            zitadel_domain: String::new(),
            zitadel_org_id: None,
            zitadel_service_user_token: None,
            base_url: "http://localhost:8080".to_string(),
        }
    }
}
