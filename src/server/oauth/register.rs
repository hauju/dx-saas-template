//! Dynamic Client Registration (RFC 7591).
//!
//! Unauthenticated on purpose: the `client_id` we hand back is not a secret. The
//! real boundary is [`super::redirect_uri_allowed`], which restricts callbacks to
//! known MCP hosts and loopback.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use super::{redirect_uri_allowed, store};
use crate::server::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
}

fn error(code: StatusCode, error: &str, description: &str) -> Response {
    (
        code,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

pub async fn register(state: AppState, Json(req): Json<RegisterRequest>) -> Response {
    if req.redirect_uris.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "at least one redirect_uri is required",
        );
    }
    if let Some(bad) = req.redirect_uris.iter().find(|u| !redirect_uri_allowed(u)) {
        tracing::warn!(redirect_uri = %bad, "rejected client registration: redirect_uri not allowed");
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri is not on the allowlist",
        );
    }

    let client_id = match crypto::generate_invitation_token() {
        Ok(t) => format!("mcp_{t}"),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "id generation failed",
            );
        }
    };

    let entity = match store::insert_client(
        &state.db,
        uuid::Uuid::new_v4(),
        &client_id,
        &req.redirect_uris,
        req.client_name.as_deref(),
    )
    .await
    {
        Ok(entity) => entity,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not persist client",
            );
        }
    };

    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": entity.client_id,
            "redirect_uris": entity.redirect_uris,
            "client_name": entity.client_name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        })),
    )
        .into_response()
}
