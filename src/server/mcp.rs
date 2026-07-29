//! MCP (Model Context Protocol) endpoint backed by `rmcp` over Streamable HTTP.
//!
//! `POST /mcp` is served by rmcp's [`StreamableHttpService`] (JSON-RPC in,
//! SSE/JSON out). Tools live on [`McpTools`] via the `#[tool_router]` / `#[tool]`
//! macros and pull the authenticated user from the request headers using the
//! shared [`api_auth::authenticate`] logic.
//!
//! Auth is two-layered: [`mcp_auth_challenge`] does a presence-only check at the
//! edge (no credential → `401` + `WWW-Authenticate` pointing at the
//! protected-resource metadata, which triggers the OAuth discovery flow); each
//! tool then performs the real API-key / JWT validation.

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::handler::server::tool::{Extension, ToolRouter};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::server::api_auth::{self, ApiAuth, AuthVia};
use crate::server::security::{IpRateLimiter, ip_rate_limit};
use crate::server::state::AppState;

/// The MCP server: holds app state and the generated tool router.
#[derive(Clone)]
pub struct McpTools {
    state: AppState,
    tool_router: ToolRouter<Self>,
}

impl McpTools {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    /// Resolve the authenticated user from the request headers, or an MCP error.
    async fn authenticate(&self, parts: &Parts) -> Result<ApiAuth, McpError> {
        api_auth::authenticate(&self.state, &parts.headers)
            .await
            .map_err(|_| {
                McpError::invalid_request(
                    "Missing or invalid credential. Provide 'Authorization: Bearer <token>' or 'X-API-Key: <token>'.",
                    None,
                )
            })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EchoInput {
    /// The message to echo back.
    pub message: String,
}

#[tool_router]
impl McpTools {
    /// Return the authenticated user's account.
    #[tool(
        description = "Return the authenticated user's account: email, id, and how the request authenticated."
    )]
    pub async fn whoami(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.authenticate(&parts).await?;
        let via = match auth.via {
            AuthVia::ApiKey => "api_key",
            AuthVia::Jwt => "jwt",
        };
        let text = format!(
            "Authenticated as {} (id {}) via {}.",
            auth.user.email, auth.user.id, via
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Echo back the provided message.
    #[tool(description = "Echo back the provided message.")]
    pub async fn echo(
        &self,
        Extension(parts): Extension<Parts>,
        params: Parameters<EchoInput>,
    ) -> Result<CallToolResult, McpError> {
        // Require auth so the whole endpoint is uniformly protected.
        self.authenticate(&parts).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            params.0.message,
        )]))
    }
}

/// `#[tool_handler]` generates `call_tool`, `list_tools`, and `get_tool`. The
/// explicit `router = self.tool_router` matters: the attribute otherwise defaults
/// to `Self::tool_router()`, which rebuilds the router — re-deriving every tool's
/// JSON schema — on every `tools/list` and `tools/call`. Pointing it at the field
/// reuses the one built in [`McpTools::new`].
///
/// The remaining trait methods — notably `initialize` — keep their defaults, which
/// negotiate the protocol version against what the client asked for and record the
/// peer info. That negotiation matters under the `2026-07-28` spec: per SEP-2567
/// the version decides whether a request is served statelessly, so pinning it to
/// the server's own default (as a hand-written `initialize` would) breaks older
/// clients.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("dx-saas-template", env!("CARGO_PKG_VERSION"))
                    .with_title("dx-saas-template MCP"),
            )
            .with_instructions(
                "Authenticate with an API key via 'Authorization: Bearer <token>' or \
                 'X-API-Key: <token>'. Tools: whoami, echo.",
            )
    }
}

/// Presence-only OAuth challenge for `/mcp` (RFC 9728).
///
/// Any `Bearer`/`X-API-Key` credential passes through here; the actual validation
/// happens inside each tool. With no credential we return `401` plus a
/// `WWW-Authenticate` header pointing at the protected-resource metadata, which
/// is what makes an MCP client (e.g. Claude) start its OAuth discovery flow.
pub async fn mcp_auth_challenge(
    axum::Extension(state): axum::Extension<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let has_bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .is_some_and(|t| !t.trim().is_empty());
    let has_x_api_key = headers
        .get("x-api-key")
        .is_some_and(|v| v.to_str().is_ok_and(|s| !s.trim().is_empty()));

    if has_bearer || has_x_api_key {
        return next.run(request).await;
    }

    let metadata_url = format!(
        "{}/.well-known/oauth-protected-resource",
        state.config.base_url.trim_end_matches('/')
    );
    let challenge = format!("Bearer resource_metadata=\"{metadata_url}\"");
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
    )
        .into_response()
}

/// Hosts accepted in the `Host` header of `/mcp` requests.
///
/// rmcp validates `Host` to block DNS rebinding, and its default allowlist is
/// loopback-only — which would reject every request to a deployed instance. The
/// deployment's own hostname comes from `BASE_URL`; loopback stays on the list so
/// local development and container health checks keep working.
///
/// Entries are bare hostnames, without a port, because rmcp treats a portless
/// entry as "any port": the public URL and the port the process actually listens
/// on differ behind a reverse proxy.
fn allowed_hosts(base_url: &str) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(host) = url::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        && !hosts.contains(&host)
    {
        hosts.push(host);
    }
    hosts
}

/// Build the `/mcp` router: rmcp Streamable-HTTP service + auth challenge + rate
/// limit.
///
/// The service factory builds a fresh [`McpTools`] per session — and, for clients
/// negotiating `2026-07-28`, per request, since SEP-2567 drops sessions from that
/// version. Keep the factory cheap for that reason: it clones [`AppState`]
/// (pool handles behind `Arc`) and builds the tool router, nothing more.
pub fn mcp_router(state: AppState, trust_proxy_headers: bool) -> Router {
    let limiter =
        IpRateLimiter::shared_per_minute(state.db.pool.clone(), "mcp", 120, trust_proxy_headers);
    let session_manager = Arc::new(LocalSessionManager::default());
    let server_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts(&state.config.base_url));

    let service = StreamableHttpService::new(
        move || Ok(McpTools::new(state.clone())),
        session_manager,
        server_config,
    );

    Router::new()
        .route_service("/mcp", service)
        .layer(axum::middleware::from_fn(mcp_auth_challenge))
        .layer(axum::middleware::from_fn(ip_rate_limit))
        .layer(axum::Extension(limiter))
}

#[cfg(test)]
mod tests {
    use super::allowed_hosts;

    #[test]
    fn deployment_host_is_derived_from_base_url() {
        let hosts = allowed_hosts("https://app.example.com");
        assert!(hosts.contains(&"app.example.com".to_string()));
    }

    #[test]
    fn port_is_stripped_so_any_port_matches() {
        // rmcp treats a portless entry as "any port"; keeping the port would
        // reject requests whose Host carries the proxy's port instead.
        let hosts = allowed_hosts("https://app.example.com:8443");
        assert!(hosts.contains(&"app.example.com".to_string()));
        assert!(!hosts.iter().any(|h| h.contains(':') && h != "::1"));
    }

    #[test]
    fn loopback_is_always_allowed() {
        let hosts = allowed_hosts("https://app.example.com");
        for expected in ["localhost", "127.0.0.1", "::1"] {
            assert!(hosts.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[test]
    fn local_base_url_does_not_duplicate_loopback() {
        let hosts = allowed_hosts("http://localhost:8080");
        assert_eq!(hosts.iter().filter(|h| *h == "localhost").count(), 1);
    }

    #[test]
    fn unparseable_base_url_still_leaves_loopback() {
        let hosts = allowed_hosts("not a url");
        assert_eq!(hosts, vec!["localhost", "127.0.0.1", "::1"]);
    }
}
