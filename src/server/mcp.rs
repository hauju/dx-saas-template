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
use rmcp::handler::server::tool::{Extension, ToolCallContext, ToolRouter};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, Implementation, InitializeRequestParams,
    InitializeResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
    Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{tool, tool_router};
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
            auth.user.email,
            auth.user.id.to_hex(),
            via
        );
        Ok(CallToolResult::success(vec![Content::text(text)]))
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
        Ok(CallToolResult::success(vec![Content::text(
            params.0.message,
        )]))
    }
}

impl ServerHandler for McpTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "dx-saas-template".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("dx-saas-template MCP".to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "Authenticate with an API key via 'Authorization: Bearer <token>' or \
                 'X-API-Key: <token>'. Tools: whoami, echo."
                    .to_string(),
            ),
        }
    }

    // The trait requires `-> impl Future + Send`; a plain `async fn` can't carry
    // the `Send` bound here, so the explicit future is intentional.
    #[allow(clippy::manual_async_fn)]
    fn initialize(
        &self,
        _request: InitializeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<InitializeResult, McpError>> + Send + '_ {
        async {
            let info = self.get_info();
            Ok(InitializeResult {
                protocol_version: info.protocol_version,
                capabilities: info.capabilities,
                server_info: info.server_info,
                instructions: info.instructions,
            })
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async {
            let tools: Vec<Tool> = self.tool_router.list_all();
            Ok(ListToolsResult {
                tools,
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        let tool_context = ToolCallContext::new(self, request, context);
        self.tool_router.call(tool_context)
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

/// Build the `/mcp` router: rmcp Streamable-HTTP service + auth challenge + rate
/// limit. A fresh [`McpTools`] is created per session via the service factory.
pub fn mcp_router(state: AppState, trust_proxy_headers: bool) -> Router {
    let limiter = IpRateLimiter::per_minute(120, trust_proxy_headers);
    let session_manager = Arc::new(LocalSessionManager::default());
    let server_config = StreamableHttpServerConfig::default();

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
