//! OAuth discovery metadata.
//!
//! - Protected Resource Metadata (RFC 9728) tells the MCP client which
//!   authorization server protects `/mcp`.
//! - Authorization Server Metadata (RFC 8414) describes our endpoints. We issue
//!   opaque `oat_` tokens (not JWTs), so there is no `jwks_uri`.

use axum::Json;
use axum::response::IntoResponse;
use serde_json::json;

use crate::server::state::AppState;

fn base(state: &AppState) -> String {
    state.config.base_url.trim_end_matches('/').to_string()
}

/// `GET /.well-known/oauth-protected-resource[/mcp]`
pub async fn protected_resource(state: AppState) -> impl IntoResponse {
    let base = base(&state);
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }))
}

/// `GET /.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`
pub async fn authorization_server(state: AppState) -> impl IntoResponse {
    let base = base(&state);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp"],
    }))
}
