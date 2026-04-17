//! IP-based rate limiting middleware for auth endpoints.
//!
//! Uses `governor` for per-IP keyed rate limiting.
//! IP is extracted from `X-Forwarded-For`, `X-Real-IP`, or `Forwarded` headers,
//! with a fallback to `"unknown"`.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    Extension,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, state::keyed::DefaultKeyedStateStore};

/// Keyed rate limiter: one bucket per IP string.
type KeyedLimiter =
    RateLimiter<String, DefaultKeyedStateStore<String>, governor::clock::DefaultClock>;

/// Wrapper so we can put it in an `Extension`.
#[derive(Clone)]
pub struct AuthRateLimiter {
    inner: Arc<KeyedLimiter>,
}

impl AuthRateLimiter {
    /// Create a new rate limiter allowing `per_minute` requests per IP per minute.
    pub fn new(per_minute: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(per_minute).expect("per_minute must be > 0"));
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}

/// Extract the client IP address from common reverse-proxy headers.
///
/// Checks (in order): `X-Forwarded-For`, `X-Real-IP`, `Forwarded`.
/// Falls back to `"unknown"` if none are present.
fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    // X-Forwarded-For: client, proxy1, proxy2 — take the first (leftmost)
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = xff.split(',').next()
    {
        let ip = first.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }

    // X-Real-IP: single IP
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = real_ip.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }

    // Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
    if let Some(fwd) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for part in fwd.split(';') {
            let part = part.trim();
            if let Some(ip) = part.strip_prefix("for=") {
                let ip = ip.trim().trim_matches('"');
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    "unknown".to_string()
}

/// Axum middleware that enforces per-IP rate limiting.
///
/// Returns `429 Too Many Requests` when the limit is exceeded.
pub async fn rate_limit_middleware(
    Extension(limiter): Extension<AuthRateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(request.headers());

    match limiter.inner.check_key(&ip) {
        Ok(_) => next.run(request).await,
        Err(_not_until) => {
            tracing::warn!(ip = %ip, "Auth rate limit exceeded");
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests. Please try again later.",
            )
                .into_response()
        }
    }
}
