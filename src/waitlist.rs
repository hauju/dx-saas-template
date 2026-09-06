//! Pre-launch waitlist: the server function that records an address, the
//! form that posts to it, and the site flags that tell the client whether the
//! coming-soon page is on. Dual-target like `api_keys`.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
use crate::models::AppError;

use crate::pages::login::get_captcha_config;

/// Deployment flags the client needs before it can render the right page.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct SiteFlags {
    /// `COMING_SOON=true`: `/` is the coming-soon page with the waitlist
    /// instead of the landing page, and the navbar stays hidden. Login, docs
    /// and the dashboard remain reachable at their URLs.
    pub coming_soon: bool,
}

#[get("/api/site")]
pub async fn get_site_flags() -> Result<SiteFlags, ServerFnError> {
    Ok(SiteFlags {
        coming_soon: crate::server::state::AppState::global().config.coming_soon,
    })
}

/// The flags `App` fetched, for the navbar and the home route.
///
/// Read straight from the resource rather than through an effect so the
/// server render and the hydrated one agree: a flash of the landing page on a
/// coming-soon site is exactly what the flag exists to prevent. While the
/// fetch is pending or failed, the site is treated as launched.
pub fn use_site_flags() -> SiteFlags {
    let flags = use_context::<Resource<Result<SiteFlags, ServerFnError>>>();
    match flags() {
        Some(Ok(flags)) => flags,
        _ => SiteFlags::default(),
    }
}

/// Record an address on the waitlist.
///
/// The one unauthenticated write in the app, so it carries its own quota
/// (5/min per IP, counted in PostgreSQL like the auth routes) and, when a
/// captcha is configured, the widget token from the form. Errors are flat
/// except validation, which describes the caller's own input.
#[post("/api/waitlist", headers: axum::http::HeaderMap, peer: axum::extract::ConnectInfo<std::net::SocketAddr>)]
pub async fn join_waitlist(email: String, captcha_token: String) -> Result<(), ServerFnError> {
    // Before anything else: a malformed address should not cost a round trip.
    let email = crate::models::waitlist::validate_email(&email)
        .map_err(|e| ServerFnError::from(AppError::Validation(e)))?;

    let state = crate::server::state::AppState::global();
    let key = crate::server::security::rate_limit_key(
        &headers,
        Some(peer.0),
        state.config.trust_proxy_headers,
    );
    let limiter = crate::server::rate_limit::SharedRateLimiter::per_minute(
        state.db.pool.clone(),
        "waitlist",
        5,
    );
    // Fail open on a database error, as the other shared limiters do: the
    // insert below needs the same database and will fail on its own.
    if !limiter.check(&key).await.unwrap_or(true) {
        return Err(ServerFnError::from(AppError::LimitExceeded(
            "too many attempts, please try again in a minute".into(),
        )));
    }

    if crate::server::captcha::configured(state) {
        match crate::server::captcha::verify(state, &captcha_token).await {
            Ok(true) => {}
            // A verdict, and it was no. Deliberately vague: naming which check
            // failed tells a bot which one to fix.
            Ok(false) => {
                return Err(ServerFnError::from(AppError::Validation(
                    "that didn't look like a human submission — please reload and try again".into(),
                )));
            }
            // No verdict. Fail closed: a confirmation for a signup that was
            // never written is worse than an error the visitor can retry.
            Err(e) => {
                tracing::error!("captcha verification was unreachable: {e}");
                return Err(ServerFnError::from(AppError::Internal(
                    "we could not check that submission right now — please try again shortly"
                        .into(),
                )));
            }
        }
    }

    crate::server::waitlist::join(&state.db, &email).await?;
    // The address stays out of the log: it is the one piece of personal data
    // this endpoint handles, and the row is where it belongs.
    tracing::info!("waitlist signup");
    Ok(())
}

/// Email capture for the coming-soon page.
///
/// Mounts the Bollwark widget inside the form when a captcha is configured,
/// with the same markup dx-auth's login page uses, and reads the hidden
/// `captcha-token` input the widget injects on submit. With no captcha the
/// token is empty and the server reads that as "captcha off".
#[component]
pub fn WaitlistForm() -> Element {
    let captcha = use_server_future(move || async move { get_captcha_config().await })?;
    let captcha_config = match captcha() {
        Some(Ok(cfg)) => cfg,
        _ => None,
    };

    let mut email = use_signal(String::new);
    let mut pending = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut joined = use_signal(|| false);

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if pending() {
            return;
        }
        let value = email();

        spawn(async move {
            pending.set(true);
            error.set(None);

            let token = document::eval(
                "const el = document.querySelector('input[name=\"captcha-token\"]');\
                 dioxus.send(el ? el.value : '');",
            )
            .recv::<String>()
            .await
            .unwrap_or_default();

            match join_waitlist(value, token).await {
                Ok(()) => joined.set(true),
                Err(e) => error.set(Some(e.to_string())),
            }
            pending.set(false);
        });
    };

    rsx! {
        if joined() {
            div { class: "alert alert-success rounded-xl max-w-md", role: "status",
                span { "You're on the list. We'll email you when it opens." }
            }
        } else {
            form { class: "flex flex-col sm:flex-row gap-2 w-full max-w-md", onsubmit: submit,
                input {
                    r#type: "email",
                    name: "email",
                    autocomplete: "email",
                    required: true,
                    placeholder: "you@example.com",
                    class: "input input-bordered flex-1 rounded-xl",
                    value: "{email}",
                    oninput: move |e| email.set(e.value()),
                }
                if let Some((server_url, site_key)) = captcha_config.clone() {
                    document::Script { src: "{server_url}/v1/widget.js", defer: true }
                    div {
                        id: "bollwark-container",
                        class: "flex justify-center",
                        "data-sitekey": "{site_key}",
                        "data-server-url": "{server_url}",
                        "data-mode": "invisible",
                    }
                }
                button {
                    r#type: "submit",
                    class: "btn btn-primary btn-strong rounded-xl",
                    disabled: pending(),
                    if pending() { "Adding you…" } else { "Join the waitlist" }
                }
            }
            if let Some(e) = error() {
                p { class: "text-error text-sm mt-3", role: "alert", "{e}" }
            }
        }
    }
}
