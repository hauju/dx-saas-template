//! Token endpoint: exchange an authorization code (+ PKCE verifier) for an
//! opaque `oat_` access token minted through the API-key store.

use axum::Form;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use super::store;
use crate::server::api_key::{self, ClientBinding};
use crate::server::state::AppState;

/// How long an access token minted for an MCP client stays valid. There is no
/// refresh token: when it expires the client gets a 401 and, per the MCP
/// authorization spec, runs the OAuth flow again, so this is the longest a
/// consent outlives the person who gave it.
pub const ACCESS_TOKEN_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
}

/// OAuth error responses must be JSON with `Cache-Control: no-store`.
fn token_error(code: StatusCode, error: &str) -> Response {
    (
        code,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error })),
    )
        .into_response()
}

use axum::Json;

pub async fn token(state: AppState, Form(form): Form<TokenForm>) -> Response {
    if form.grant_type.as_deref() != Some("authorization_code") {
        return token_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let (Some(code), Some(verifier)) = (form.code.as_deref(), form.code_verifier.as_deref()) else {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    };

    let entry = match store::take_code(&state.db, code).await {
        Ok(Some(e)) => e,
        Ok(None) => return token_error(StatusCode::BAD_REQUEST, "invalid_grant"),
        Err(_) => return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };

    // Defense in depth: the TTL index reaps expired codes, but check explicitly.
    if entry.expires_at < chrono::Utc::now() {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    if form
        .client_id
        .as_deref()
        .is_some_and(|c| c != entry.client_id)
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    if form
        .redirect_uri
        .as_deref()
        .is_some_and(|r| r != entry.redirect_uri)
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    if !crypto::verify_pkce_s256(verifier, &entry.code_challenge) {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    // Mint a long-lived opaque token that the API/MCP dual-auth path validates.
    let binding = ClientBinding {
        client_id: &entry.client_id,
        scope: &entry.scope,
        ttl_seconds: ACCESS_TOKEN_TTL_SECONDS as f64,
    };
    let access_token =
        match api_key::create_for_client(&state.db, entry.user_id, "Claude (MCP)", binding).await {
            Ok((token, _)) => token,
            Err(e) => {
                tracing::error!("failed to mint MCP access token: {e}");
                return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
            }
        };

    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            "scope": entry.scope,
        })),
    )
        .into_response()
}
