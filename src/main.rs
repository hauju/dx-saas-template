use dioxus::prelude::*;

mod api_keys;
mod components;
mod models;
mod pages;
pub mod routes;
mod subscription;

#[cfg(feature = "server")]
mod server;

use components::toast::{ToastManager, ToastProvider};
use models::user::LoggedInData;

pub const FAVICON: Asset = asset!("/assets/favicon.ico");
pub const MAIN_CSS: Asset = asset!("/assets/main.css");
pub const HEADER_SVG: Asset = asset!("/assets/header.svg");
pub const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

/// Inline JS that sets `data-theme` on `<html>` from `prefers-color-scheme`
/// **before** first paint. Without this, SSR ships HTML with no `data-theme`,
/// DaisyUI uses its default, and any `use_effect`-based correction runs after
/// hydration, causing a theme flash.
const THEME_BOOTSTRAP_JS: &str = r#"
(function () {
    var root = document.documentElement;
    var apply = function (dark) {
        root.setAttribute('data-theme', dark ? 'dark' : 'light');
        root.setAttribute('data-color-mode', dark ? 'dark' : 'light');
        root.style.colorScheme = dark ? 'dark' : 'light';
    };
    var stored = null;
    try { stored = localStorage.getItem('theme'); } catch (e) {}
    var mql = window.matchMedia('(prefers-color-scheme: dark)');
    if (stored === 'dark' || stored === 'light') {
        apply(stored === 'dark');
    } else {
        apply(mql.matches);
    }
    mql.addEventListener('change', function (e) {
        var s = null;
        try { s = localStorage.getItem('theme'); } catch (e) {}
        if (s !== 'dark' && s !== 'light') { apply(e.matches); }
    });
})();
"#;

/// Registers the service worker (`/sw.js`) once the page has loaded, enabling
/// PWA install. The worker itself is inert on localhost, so this is safe to
/// emit in every build.
const SW_REGISTER_JS: &str = r#"
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
        navigator.serviceWorker.register('/sw.js').catch(function () {});
    });
}
"#;

/// Client-side authentication state.
#[derive(Clone, Debug, PartialEq)]
pub enum UserAuthState {
    Loading,
    Authenticated(LoggedInData),
    NotAuthenticated,
}

// ============================================================================
// Server main
// ============================================================================

#[cfg(feature = "server")]
#[tokio::main]
async fn main() {
    use std::sync::Arc;

    use axum::Extension;
    use tower_http::compression::CompressionLayer;
    use tower_http::trace::TraceLayer;
    use tower_sessions::cookie::time::Duration;
    use tower_sessions::{ExpiredDeletion, Expiry, SessionManagerLayer};
    use tower_sessions_sqlx_store::PostgresStore;

    use server::auth_store::{AppAuthUserStore, AppEmailSender};
    use server::state::AppState;

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // Install rustls crypto provider before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize Sentry before the tracing subscriber so the tracing layer can forward events.
    #[cfg(feature = "sentry")]
    let _sentry_guard = sentry::init((
        std::env::var("SENTRY_DSN").ok(),
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: std::env::var("ENVIRONMENT")
                .ok()
                .map(std::borrow::Cow::from),
            ..Default::default()
        },
    ));

    let registry = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true),
        )
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,dx_saas_template=debug".parse().unwrap()),
        );

    #[cfg(feature = "sentry")]
    let registry = registry.with(
        sentry::integrations::tracing::layer().event_filter(|metadata| match *metadata.level() {
            tracing::Level::ERROR => sentry::integrations::tracing::EventFilter::Event,
            _ => sentry::integrations::tracing::EventFilter::Breadcrumb,
        }),
    );

    registry.init();

    // Initialize AppState (loads config, connects to DB)
    let app_state = AppState::init()
        .await
        .expect("Failed to initialize AppState");
    tracing::info!("AppState initialized");

    // PostgreSQL session store (reuses the application connection pool)
    let session_store = PostgresStore::new(app_state.db.pool.clone());
    session_store
        .migrate()
        .await
        .expect("Failed to migrate session store");

    // Drop elapsed rate-limit windows periodically (see server::rate_limit).
    server::rate_limit::spawn_sweeper(app_state.db.pool.clone());

    // Prune expired sessions hourly so the table doesn't grow unbounded.
    let _deletion_task = tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(60 * 60)),
    );

    // Session layer
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(app_state.config.secure_cookies)
        .with_expiry(Expiry::OnInactivity(Duration::days(7)))
        .with_signed(
            tower_sessions::cookie::Key::try_from(app_state.secrets.session_secret.as_slice())
                .expect("Invalid session secret"),
        );

    // Auth router
    let auth_config = auth::AuthConfig {
        login_page_url: "/login".to_string(),
        default_post_login_url: "/dashboard".to_string(),
        dev_login_url: "/login".to_string(),
        ferriskey_url: app_state.config.ferriskey_url.clone(),
        ferriskey_issuer_url: app_state.config.ferriskey_issuer_url.clone(),
        ferriskey_realm: app_state.config.ferriskey_realm.clone(),
        ferriskey_client_id: app_state.config.ferriskey_client_id.clone(),
        ferriskey_client_secret: app_state.secrets.ferriskey_client_secret.clone(),
        base_url: app_state.config.base_url.clone(),
        trust_proxy_headers: app_state.config.trust_proxy_headers,
    };

    let auth_state = auth::AuthState {
        user_store: Arc::new(AppAuthUserStore::new(app_state.clone())),
        email_sender: Arc::new(AppEmailSender::new(app_state.clone())),
        jwks_cache: app_state.jwks.clone(),
        // Count auth attempts in PostgreSQL so the quota is enforced once
        // across every replica, not once per process.
        rate_limit_store: Some(Arc::new(server::rate_limit::AppAuthRateLimitStore::new(
            app_state.db.pool.clone(),
            auth::AUTH_REQUESTS_PER_MINUTE,
        ))),
    };

    let auth_routes = auth::auth_router(auth_config, auth_state);

    // Build the Dioxus server router with layers
    let address = dioxus::cli_config::fullstack_address_or_localhost();

    // HSTS is only safe over HTTPS, so gate it on the same flag as secure cookies.
    let hsts = app_state.config.secure_cookies;
    let trust_proxy = app_state.config.trust_proxy_headers;
    // Global per-IP backstop against abuse; sensitive sub-routers add stricter quotas.
    let global_rate_limiter = server::security::IpRateLimiter::per_minute(600, trust_proxy);

    let router = dioxus::server::router(App)
        .merge(auth_routes)
        // OAuth 2.1 authorization server + MCP connector (see src/server/oauth, mcp).
        .merge(server::oauth::oauth_router(
            app_state.db.pool.clone(),
            trust_proxy,
        ))
        .merge(server::mcp::mcp_router(app_state.clone(), trust_proxy))
        // Polar billing webhook (see src/server/billing).
        .merge(server::billing::billing_router(
            app_state.db.pool.clone(),
            trust_proxy,
        ))
        // PWA manifest, service worker, and app icons (see src/server/pwa).
        .merge(server::pwa::pwa_router())
        // GET /health — readiness probe used by the Docker HEALTHCHECK.
        .merge(server::health::health_router())
        .layer(session_layer)
        .layer(CompressionLayer::new())
        .layer(Extension(app_state))
        // Per-IP rate-limit backstop (Extension must sit outside the middleware).
        .layer(axum::middleware::from_fn(server::security::ip_rate_limit))
        .layer(Extension(global_rate_limiter))
        // Hardening headers on every response (including errors above).
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut res = next.run(req).await;
                server::security::apply_security_headers(res.headers_mut(), hsts);
                res
            },
        ))
        // Outermost: a request span that records the path only (never the query).
        .layer(TraceLayer::new_for_http().make_span_with(server::security::redacted_request_span));

    tracing::info!("Listening on {address}");

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("Failed to bind TCP listener");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Server error");

    tracing::info!("Shutdown complete");
}

/// Resolves once the process is asked to stop: Ctrl-C when run locally, SIGTERM
/// from Docker/Coolify on redeploy.
///
/// Without this, a redeploy severs in-flight requests mid-response. With it,
/// the listener stops accepting and existing requests are allowed to finish.
/// Note that orchestrators follow SIGTERM with SIGKILL after a grace period
/// (Docker defaults to 10s), which no amount of draining can outlast — keep
/// long-running work off the request path.
#[cfg(feature = "server")]
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C, draining connections"),
        _ = terminate => tracing::info!("received SIGTERM, draining connections"),
    }
}

// ============================================================================
// Client main
// ============================================================================

#[cfg(not(feature = "server"))]
fn main() {
    dioxus::launch(App);
}

// ============================================================================
// App component
// ============================================================================

#[component]
fn App() -> Element {
    // Context providers
    use_context_provider(|| Signal::new(ToastManager::default()));
    use_context_provider(|| Signal::new(UserAuthState::Loading));
    let user_refresh = use_signal(auth::UserDataRefreshTrigger::default);
    use_context_provider(|| user_refresh);

    let mut user_auth = use_context::<Signal<UserAuthState>>();

    // Fetch login data (re-runs when refresh trigger bumps)
    let user_data = use_server_future(move || {
        let _ = user_refresh();
        async { get_login_data().await }
    })?;

    // Update auth state from resource result
    use_effect(move || match user_data() {
        Some(Ok(Some(data))) => {
            user_auth.set(UserAuthState::Authenticated(data));
        }
        Some(Ok(None)) | Some(Err(_)) => {
            user_auth.set(UserAuthState::NotAuthenticated);
        }
        None => {}
    });

    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        // PWA: installable web app metadata (see src/server/pwa.rs).
        document::Link { rel: "manifest", href: "/manifest.webmanifest" }
        document::Link { rel: "apple-touch-icon", href: "/apple-touch-icon.png" }
        document::Meta { name: "theme-color", content: "#0a0e14" }
        document::Meta { name: "mobile-web-app-capable", content: "yes" }
        document::Meta { name: "apple-mobile-web-app-capable", content: "yes" }
        document::Meta { name: "apple-mobile-web-app-status-bar-style", content: "black-translucent" }
        document::Meta { name: "apple-mobile-web-app-title", content: "SaaS Template" }
        document::Script { {THEME_BOOTSTRAP_JS} }
        document::Script { {SW_REGISTER_JS} }
        Router::<routes::Route> {}
        ToastProvider {}
    }
}

// ============================================================================
// Server functions
// ============================================================================

#[post("/api/me", session: auth::UserSession)]
async fn get_login_data() -> Result<Option<LoggedInData>, ServerFnError> {
    Ok(session.data().ok().map(LoggedInData::from))
}
