//! Server-wide security middleware.
//!
//! Three independent pieces, all wired in `main.rs`:
//! - [`apply_security_headers`] — hardening response headers on every response.
//! - [`redacted_request_span`] — a tracing span that records the request path
//!   only, never the query string (so tokens carried in URLs never hit logs).
//! - [`IpRateLimiter`] / [`ip_rate_limit`] — a reusable per-IP rate limiter the
//!   main router uses as a global backstop and the API / OAuth / webhook
//!   sub-routers reuse with stricter quotas.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    Extension,
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, state::keyed::DefaultKeyedStateStore};
use sqlx::PgPool;

use crate::server::rate_limit::SharedRateLimiter;

// ============================================================================
// Response headers
// ============================================================================

/// Apply hardening headers to a response.
///
/// `hsts` (true in production, mirrors `SECURE_COOKIES`) gates
/// `Strict-Transport-Security`, which must only be advertised over HTTPS.
///
/// `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`
/// together block clickjacking; the app is never meant to be framed.
pub fn apply_security_headers(headers: &mut HeaderMap, hsts: bool) {
    use axum::http::HeaderValue;

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    if hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

// ============================================================================
// Request span (query-redacted)
// ============================================================================

/// Build a request span that records the method and path only.
///
/// OAuth and SSE endpoints carry tokens in the query string; recording the full
/// URI would leak them into logs regardless of log level. We record `path()`,
/// which excludes the query.
pub fn redacted_request_span<B>(req: &axum::http::Request<B>) -> tracing::Span {
    tracing::info_span!(
        "request",
        method = %req.method(),
        path = %req.uri().path(),
    )
}

// ============================================================================
// Per-IP rate limiter
// ============================================================================

/// Keyed rate limiter: one token bucket per client-IP string.
type KeyedLimiter =
    RateLimiter<String, DefaultKeyedStateStore<String>, governor::clock::DefaultClock>;

/// Where the counters live.
#[derive(Clone)]
enum Backend {
    /// Per-process token buckets. No coordination, so an N-replica deployment
    /// allows up to N× the quota — acceptable for a coarse flood backstop.
    Local(Arc<KeyedLimiter>),
    /// Counters in PostgreSQL, shared by every replica. Costs one round-trip
    /// per request, so reserve it for low-volume routes.
    Shared(SharedRateLimiter),
}

/// A reusable per-IP rate limiter, paired with [`ip_rate_limit`] as middleware.
///
/// Insert one as an `Extension` next to the middleware on any router; nested
/// sub-routers can each carry their own quota.
#[derive(Clone)]
pub struct IpRateLimiter {
    backend: Backend,
    trust_proxy_headers: bool,
}

impl IpRateLimiter {
    /// Allow `per_minute` requests per client IP per minute, counted in-process.
    ///
    /// `trust_proxy_headers` mirrors `AuthConfig::trust_proxy_headers`: when set,
    /// the leftmost `X-Forwarded-For` hop is used as the client IP; otherwise the
    /// socket peer address is used.
    pub fn per_minute(per_minute: u32, trust_proxy_headers: bool) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(per_minute).expect("per_minute must be > 0"));
        Self {
            backend: Backend::Local(Arc::new(RateLimiter::keyed(quota))),
            trust_proxy_headers,
        }
    }

    /// Same quota, but counted in PostgreSQL so it holds across replicas.
    ///
    /// `scope` namespaces the keys, so routers with different quotas don't draw
    /// from the same bucket.
    pub fn shared_per_minute(
        pool: PgPool,
        scope: &str,
        per_minute: u32,
        trust_proxy_headers: bool,
    ) -> Self {
        Self {
            backend: Backend::Shared(SharedRateLimiter::per_minute(pool, scope, per_minute)),
            trust_proxy_headers,
        }
    }

    async fn check(&self, key: &str) -> bool {
        match &self.backend {
            Backend::Local(limiter) => limiter.check_key(&key.to_string()).is_ok(),
            // Fail open on database errors: every route behind a shared limiter
            // needs the same database to serve a real response, so rejecting
            // here would convert a database blip into a hard outage while
            // denying an attacker nothing. The global in-process backstop still
            // applies.
            Backend::Shared(limiter) => match limiter.check(key).await {
                Ok(allowed) => allowed,
                Err(e) => {
                    tracing::error!("shared rate limit check failed, allowing request: {e}");
                    true
                }
            },
        }
    }
}

fn rate_limit_key(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = xff.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return format!("fwd:{ip}");
    }

    match peer {
        Some(addr) => format!("peer:{}", addr.ip()),
        None => "peer:unknown".to_string(),
    }
}

/// Axum middleware enforcing the [`IpRateLimiter`] found in request extensions.
///
/// Returns `429 Too Many Requests` when the per-IP quota is exhausted. The peer
/// address requires the server to be served with
/// `into_make_service_with_connect_info::<SocketAddr>()`.
pub async fn ip_rate_limit(
    Extension(limiter): Extension<IpRateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    let key = rate_limit_key(
        request.headers(),
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr),
        limiter.trust_proxy_headers,
    );

    if limiter.check(&key).await {
        next.run(request).await
    } else {
        tracing::warn!(rate_limit_key = %key, "Rate limit exceeded");
        (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Please try again later.",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_peer_when_proxy_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        let peer = "203.0.113.7:443".parse().unwrap();

        assert_eq!(
            rate_limit_key(&headers, Some(peer), false),
            "peer:203.0.113.7"
        );
        assert_eq!(
            rate_limit_key(&headers, Some(peer), true),
            "fwd:198.51.100.1"
        );
    }

    #[test]
    fn takes_leftmost_forwarded_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.9, 10.0.0.1".parse().unwrap());
        assert_eq!(rate_limit_key(&headers, None, true), "fwd:198.51.100.9");
    }

    #[test]
    fn security_headers_gate_hsts() {
        let mut headers = HeaderMap::new();
        apply_security_headers(&mut headers, false);
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_none());

        apply_security_headers(&mut headers, true);
        assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_some());
    }
}
