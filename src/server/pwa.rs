//! Progressive Web App endpoints — manifest, service worker, and app icons.
//!
//! All served at fixed root paths and compiled into the binary (like the docs).
//! This sidesteps Dioxus asset hashing, which would otherwise (a) scope the
//! service worker to `/assets/` instead of the whole origin, and (b) change the
//! icon URLs baked into the static manifest on every build.

use axum::Router;
use axum::http::{HeaderName, header};
use axum::response::IntoResponse;
use axum::routing::get;

const MANIFEST: &str = include_str!("../../assets/pwa/manifest.webmanifest");
const SERVICE_WORKER: &str = include_str!("../../assets/pwa/sw.js");
const ICON_192: &[u8] = include_bytes!("../../assets/pwa/icon-192.png");
const ICON_512: &[u8] = include_bytes!("../../assets/pwa/icon-512.png");
const ICON_MASKABLE: &[u8] = include_bytes!("../../assets/pwa/icon-maskable-512.png");
const APPLE_TOUCH: &[u8] = include_bytes!("../../assets/pwa/apple-touch-icon.png");

/// Immutable icons can be cached hard; the manifest and worker script use
/// `no-cache` so updated app metadata and caching logic ship on the next visit.
const ICON_CACHE: &str = "public, max-age=31536000, immutable";

fn png(bytes: &'static [u8]) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, ICON_CACHE),
        ],
        bytes,
    )
}

pub fn pwa_router() -> Router {
    Router::new()
        .route(
            "/manifest.webmanifest",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "application/manifest+json"),
                        (header::CACHE_CONTROL, "no-cache"),
                    ],
                    MANIFEST,
                )
            }),
        )
        .route(
            "/sw.js",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/javascript"),
                        (header::CACHE_CONTROL, "no-cache"),
                        // Allow a root-scoped worker even though it lives here.
                        (HeaderName::from_static("service-worker-allowed"), "/"),
                    ],
                    SERVICE_WORKER,
                )
            }),
        )
        .route("/icons/icon-192.png", get(|| async { png(ICON_192) }))
        .route("/icons/icon-512.png", get(|| async { png(ICON_512) }))
        .route(
            "/icons/icon-maskable-512.png",
            get(|| async { png(ICON_MASKABLE) }),
        )
        .route("/apple-touch-icon.png", get(|| async { png(APPLE_TOUCH) }))
}
