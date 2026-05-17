//! Auth route builder.

use axum::{Extension, Router, routing::post};

use crate::config::AuthConfig;
use crate::csrf::csrf_origin_check;
use crate::handlers;
use crate::rate_limit::{AuthRateLimiter, rate_limit_middleware};
use crate::session;
use crate::state::AuthState;

/// Builds a Router with all authentication routes.
///
/// Routes included:
/// - `POST /auth/logout` — Logout handler
/// - `POST /auth/session/start` — Start a session (auto-detects passkey or OTP)
/// - `POST /auth/session/passkey/verify` — Verify passkey assertion
/// - `POST /auth/session/otp/verify` — Verify email OTP
/// - `POST /auth/session/otp/resend` — Resend OTP code
/// - `POST /auth/session/captcha/verify` — Verify CAPTCHA for new user registration
/// - `POST /auth/session/captcha/refresh` — Generate a new CAPTCHA image
/// - `POST /auth/session/accept-tos` — Accept Terms of Service
///
/// Security middleware included:
/// - **Rate limiting:** 20 requests/minute per IP (via `governor`)
/// - **CSRF:** Origin/Referer validation on POST requests against `base_url`
///
/// `AuthConfig` and `AuthState` are added as `Extension`s for handler access.
pub fn auth_router(auth_config: AuthConfig, auth_state: AuthState) -> Router {
    let rate_limiter = AuthRateLimiter::new(20);

    Router::new()
        // Logout (POST to prevent forced-logout via cross-site image/link tags)
        .route("/auth/logout", post(session::logout))
        // Session API v2 (custom login: auto-detect passkey/OTP)
        .route("/auth/session/start", post(handlers::start_session))
        .route(
            "/auth/session/passkey/verify",
            post(handlers::verify_passkey_handler),
        )
        .route(
            "/auth/session/otp/verify",
            post(handlers::verify_otp_handler),
        )
        .route(
            "/auth/session/otp/resend",
            post(handlers::resend_otp_handler),
        )
        .route(
            "/auth/session/password/verify",
            post(handlers::verify_password_handler),
        )
        .route(
            "/auth/session/captcha/verify",
            post(handlers::verify_captcha_handler),
        )
        .route(
            "/auth/session/captcha/refresh",
            post(handlers::refresh_captcha_handler),
        )
        .route(
            "/auth/session/accept-tos",
            post(handlers::accept_tos_handler),
        )
        // Security layers (outermost → innermost):
        // 1. Rate limiting: 20 requests/minute per IP across all auth endpoints
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        .layer(Extension(rate_limiter))
        // 2. CSRF: validate Origin/Referer on POST requests
        .layer(axum::middleware::from_fn(csrf_origin_check))
        // AuthConfig and AuthState available to all handlers via Extension
        .layer(Extension(auth_config))
        .layer(Extension(auth_state))
}
