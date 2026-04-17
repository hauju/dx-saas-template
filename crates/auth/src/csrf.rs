//! CSRF protection middleware for auth POST endpoints.
//!
//! Validates the `Origin` (or `Referer` fallback) header on POST requests
//! against the configured `base_url` to prevent cross-site request forgery.

use axum::{
    Extension,
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::Response,
};
use url::Url;

use crate::config::AuthConfig;

/// Middleware that validates Origin/Referer on POST requests.
///
/// For POST requests:
/// - Checks `Origin` header first, then `Referer` as fallback
/// - Compares scheme + host + port against `AuthConfig::base_url`
/// - Returns 403 if the origin doesn't match or is missing
///
/// GET, OPTIONS, and other methods pass through unchanged.
pub async fn csrf_origin_check(
    Extension(config): Extension<AuthConfig>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if request.method() == Method::POST {
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .or_else(|| request.headers().get(header::REFERER))
            .and_then(|v| v.to_str().ok());

        match origin {
            Some(value) => {
                if !origin_matches_base_url(value, &config.base_url) {
                    tracing::warn!(
                        "CSRF check failed: origin={value}, expected={}",
                        config.base_url
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
            }
            None => {
                tracing::warn!("CSRF check failed: no Origin or Referer header on POST");
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    Ok(next.run(request).await)
}

/// Compares the origin value against the base URL by scheme + host + port.
///
/// The `origin_value` can be a full URL (as in `Referer`) or just the origin
/// portion (`scheme://host[:port]`). Only scheme, host, and port are compared.
fn origin_matches_base_url(origin_value: &str, base_url: &str) -> bool {
    let Ok(origin) = Url::parse(origin_value) else {
        return false;
    };
    let Ok(base) = Url::parse(base_url) else {
        return false;
    };

    origin.scheme() == base.scheme()
        && origin.host() == base.host()
        && origin.port_or_known_default() == base.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_origins() {
        assert!(origin_matches_base_url(
            "https://seggwat.com",
            "https://seggwat.com"
        ));
        assert!(origin_matches_base_url(
            "http://localhost:8080",
            "http://localhost:8080"
        ));
    }

    #[test]
    fn matching_origin_with_path() {
        // Referer header includes full URL path
        assert!(origin_matches_base_url(
            "https://seggwat.com/auth/login",
            "https://seggwat.com"
        ));
    }

    #[test]
    fn mismatched_host() {
        assert!(!origin_matches_base_url(
            "https://evil.com",
            "https://seggwat.com"
        ));
    }

    #[test]
    fn mismatched_scheme() {
        assert!(!origin_matches_base_url(
            "http://seggwat.com",
            "https://seggwat.com"
        ));
    }

    #[test]
    fn mismatched_port() {
        assert!(!origin_matches_base_url(
            "http://localhost:9090",
            "http://localhost:8080"
        ));
    }

    #[test]
    fn default_ports_match() {
        // https default port is 443
        assert!(origin_matches_base_url(
            "https://seggwat.com:443",
            "https://seggwat.com"
        ));
        // http default port is 80
        assert!(origin_matches_base_url(
            "http://example.com:80",
            "http://example.com"
        ));
    }

    #[test]
    fn invalid_origin_rejected() {
        assert!(!origin_matches_base_url("not-a-url", "https://seggwat.com"));
        assert!(!origin_matches_base_url("", "https://seggwat.com"));
    }

    #[test]
    fn null_origin_rejected() {
        // Some privacy proxies send "null" as the Origin
        assert!(!origin_matches_base_url("null", "https://seggwat.com"));
    }
}
