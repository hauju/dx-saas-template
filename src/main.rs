use dioxus::prelude::*;

mod components;
mod models;
mod pages;
pub mod routes;

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
    var mql = window.matchMedia('(prefers-color-scheme: dark)');
    apply(mql.matches);
    mql.addEventListener('change', function (e) { apply(e.matches); });
})();
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
    use tower_sessions::cookie::time::Duration;
    use tower_sessions::{Expiry, SessionManagerLayer};
    use tower_sessions_redis_store::RedisStore;
    use tower_sessions_redis_store::fred::prelude::*;

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

    // Redis session store
    let redis_config = Config::from_url(&app_state.config.redis_url).expect("Invalid REDIS_URL");
    let redis_pool = Pool::new(redis_config, None, None, None, 4).expect("Redis pool error");
    redis_pool.init().await.expect("Failed to connect to Redis");
    let redis_store = RedisStore::new(redis_pool);

    // Session layer
    let session_layer = SessionManagerLayer::new(redis_store)
        .with_secure(app_state.config.secure_cookies)
        .with_expiry(Expiry::OnInactivity(Duration::hours(24)))
        .with_signed(
            tower_sessions::cookie::Key::try_from(app_state.secrets.session_secret.as_slice())
                .expect("Invalid session secret"),
        );

    // Auth router
    let auth_config = auth::AuthConfig {
        login_page_url: "/login".to_string(),
        default_post_login_url: "/dashboard".to_string(),
        zitadel_domain: app_state.config.zitadel_domain.clone(),
        zitadel_org_id: app_state.config.zitadel_org_id.clone(),
        zitadel_service_user_token: app_state.secrets.zitadel_service_user_token.clone(),
        base_url: app_state.config.base_url.clone(),
    };

    let auth_state = auth::AuthState {
        user_store: Arc::new(AppAuthUserStore::new(app_state.clone())),
        email_sender: Arc::new(AppEmailSender::new(app_state.clone())),
    };

    let auth_routes = auth::auth_router(auth_config, auth_state);

    // Build the Dioxus server router with layers
    let address = dioxus::cli_config::fullstack_address_or_localhost();

    let router = dioxus::server::router(App)
        .merge(auth_routes)
        .layer(session_layer)
        .layer(CompressionLayer::new())
        .layer(Extension(app_state));

    tracing::info!("Listening on {address}");

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("Failed to bind TCP listener");
    axum::serve(listener, router.into_make_service())
        .await
        .expect("Server error");
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
        document::Script { {THEME_BOOTSTRAP_JS} }
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
