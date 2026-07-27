//! A minimal self-hosted OAuth 2.1 authorization server for the MCP connector.
//!
//! It owns the consent flow (reusing the app's login session) and issues opaque
//! `oat_` tokens that the existing API-key path validates — so MCP clients ride
//! the same auth as the CLI. Endpoints:
//!
//! - `GET  /.well-known/oauth-protected-resource[/mcp]` — RFC 9728
//! - `GET  /.well-known/oauth-authorization-server`     — RFC 8414
//! - `GET  /.well-known/openid-configuration`           — RFC 8414 (alias)
//! - `POST /oauth/register`                             — RFC 7591 (DCR)
//! - `GET  /oauth/authorize` + `/resume`, `POST /oauth/authorize/decision`
//! - `POST /oauth/token`

mod authorize;
mod metadata;
mod register;
pub mod store;
mod token;

use axum::Extension;
use axum::Router;
use axum::routing::{get, post};

use crate::server::security::{IpRateLimiter, ip_rate_limit};

/// Is this `redirect_uri` allowed for dynamic client registration?
///
/// The `client_id` isn't a secret, so this allowlist is the real security
/// boundary: only known MCP callback hosts and loopback (local dev / inspector).
pub fn redirect_uri_allowed(uri: &str) -> bool {
    const EXACT: &[&str] = &[
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
    ];
    if EXACT.contains(&uri) {
        return true;
    }
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    url.scheme() == "http"
        && matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        )
}

/// Build the OAuth router. `trust_proxy_headers` is forwarded to the per-IP
/// rate limiter so the client IP is read correctly behind a reverse proxy.
pub fn oauth_router(pool: sqlx::PgPool, trust_proxy_headers: bool) -> Router {
    // Discovery metadata is static JSON that touches no database, and a client
    // re-runs discovery freely. Keeping it on an in-process limiter avoids a
    // pointless round-trip per request, and — more importantly — stops discovery
    // traffic from draining the budget that protects token issuance below.
    let metadata_limiter = IpRateLimiter::per_minute(120, trust_proxy_headers);
    let metadata_routes = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server),
        )
        .route(
            "/.well-known/openid-configuration",
            get(metadata::authorization_server),
        )
        .layer(axum::middleware::from_fn(ip_rate_limit))
        .layer(Extension(metadata_limiter));

    // Shared counter: client registration and token issuance must not scale with
    // replica count.
    let limiter = IpRateLimiter::shared_per_minute(pool, "oauth", 60, trust_proxy_headers);
    let server_routes = Router::new()
        .route("/oauth/register", post(register::register))
        .route("/oauth/authorize", get(authorize::authorize))
        .route("/oauth/authorize/resume", get(authorize::resume))
        .route("/oauth/authorize/decision", post(authorize::decision))
        .route("/oauth/token", post(token::token))
        .layer(axum::middleware::from_fn(ip_rate_limit))
        .layer(Extension(limiter));

    metadata_routes.merge(server_routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_claude_callbacks_and_loopback() {
        assert!(redirect_uri_allowed(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(redirect_uri_allowed(
            "https://claude.com/api/mcp/auth_callback"
        ));
        assert!(redirect_uri_allowed("http://localhost:8765/callback"));
        assert!(redirect_uri_allowed("http://127.0.0.1/cb"));
    }

    #[test]
    fn rejects_arbitrary_and_https_non_claude() {
        assert!(!redirect_uri_allowed("https://evil.example.com/callback"));
        assert!(!redirect_uri_allowed(
            "https://claude.ai.evil.com/api/mcp/auth_callback"
        ));
        assert!(!redirect_uri_allowed("http://example.com/callback"));
        assert!(!redirect_uri_allowed("not-a-url"));
    }
}
