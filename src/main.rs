use dioxus::prelude::*;

mod api_keys;
mod components;
mod models;
mod pages;
pub mod routes;
mod subscription;
mod waitlist;

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

    // Every route and middleware layer lives in server::router so the HTTP
    // tests can drive the identical stack (see that module).
    let router = server::router::build(dioxus::server::router(App), app_state).await;

    let address = dioxus::cli_config::fullstack_address_or_localhost();

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

    // Deployment flags (coming-soon mode), fetched once and read by the navbar
    // and the home route through `waitlist::use_site_flags`.
    let site_flags = use_server_future(move || async move { waitlist::get_site_flags().await })?;
    use_context_provider(|| site_flags);

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
