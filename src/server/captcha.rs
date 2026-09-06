//! Server-side Bollwark verification for the forms the app owns.
//!
//! dx-auth verifies the login page's tokens itself; this is the same call for
//! the waitlist. It reads the public pair from `Config::captcha` and the
//! secret from `Secrets`, so a deployment with no captcha configured never
//! reaches the network.

use std::sync::OnceLock;

use crate::models::AppError;
use crate::server::state::AppState;

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client")
    })
}

/// Whether this deployment gates its forms with a captcha at all.
pub fn configured(state: &AppState) -> bool {
    state.config.captcha.is_some()
}

/// Verify a widget token server-to-server.
///
/// `Ok(false)` is a verdict (a bot, a stale token, or no token at all); `Err`
/// means no verdict could be had, which callers should treat as a retryable
/// failure rather than as a pass.
pub async fn verify(state: &AppState, token: &str) -> Result<bool, AppError> {
    let (Some((server_url, _)), Some(secret)) =
        (&state.config.captcha, &state.secrets.captcha_secret_key)
    else {
        return Err(AppError::Internal("captcha is not configured".into()));
    };
    if token.is_empty() {
        return Ok(false);
    }

    let resp = client()
        .post(format!("{}/v1/verify", server_url.trim_end_matches('/')))
        .bearer_auth(secret)
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("captcha verify request failed: {e}")))?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let success = body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(status.is_success() && success)
}
