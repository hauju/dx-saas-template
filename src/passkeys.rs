//! Passkey management: server functions to list and remove a user's passkeys
//! (`AUTH_MODE=local`, where this app is the WebAuthn Relying Party) and the
//! Settings card that also enrolls a new one through dx-auth's browser helper.
//! Dual-target like `api_keys`.

use dioxus::prelude::*;

#[cfg(feature = "server")]
use crate::models::AppError;

use crate::components::toast::{ToastLevel, show_toast};
use crate::models::passkey::PasskeySummary;
use crate::waitlist::use_site_flags;

// ============================================================================
// Server functions
// ============================================================================

#[post("/api/passkeys/list", session: auth::UserSession)]
pub async fn list_passkeys() -> Result<Vec<PasskeySummary>, ServerFnError> {
    let data = session
        .data()
        .map_err(|_| ServerFnError::from(AppError::Unauthorized))?;
    let state = crate::server::state::AppState::global();
    let user_id = uuid::Uuid::parse_str(&data.id)
        .map_err(|e| ServerFnError::from(AppError::Validation(format!("invalid user id: {e}"))))?;
    Ok(crate::server::passkey_store::list_summaries(&state.db, user_id).await?)
}

/// Remove one of the caller's passkeys. The store scopes the delete by owner,
/// so someone else's id removes nothing and reads as not found.
#[post("/api/passkeys/delete", session: auth::UserSession)]
pub async fn delete_passkey(id: String) -> Result<(), ServerFnError> {
    use auth::AuthPasskeyStore;

    let data = session
        .data()
        .map_err(|_| ServerFnError::from(AppError::Unauthorized))?;
    let state = crate::server::state::AppState::global();
    let removed = crate::server::passkey_store::AppAuthPasskeyStore::new(state.clone())
        .delete_passkey(&data.id, &id)
        .await
        .map_err(|e| ServerFnError::from(AppError::Internal(e.to_string())))?;
    if !removed {
        return Err(ServerFnError::from(AppError::NotFound));
    }
    Ok(())
}

// ============================================================================
// UI
// ============================================================================

/// Settings card: the user's passkeys, with removal and labelled enrollment.
///
/// Renders nothing outside local auth mode: in FerrisKey mode passkeys belong
/// to the identity provider. The hooks run either way so their order does not
/// change when the site flags resolve.
#[component]
pub fn PasskeysCard() -> Element {
    let local = use_site_flags().local_login;
    let mut refresh = use_signal(|| 0u32);
    let passkeys = use_resource(move || async move {
        refresh();
        list_passkeys().await
    });

    let mut name = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut enrolling = use_signal(|| false);

    let enroll = move |_| {
        if enrolling() {
            return;
        }
        enrolling.set(true);
        error.set(None);
        let label = name.peek().trim().to_string();
        spawn(async move {
            #[cfg(feature = "web")]
            {
                let label = (!label.is_empty()).then_some(label);
                match auth::webauthn_helpers::enroll_passkey_named(label.as_deref()).await {
                    Ok(()) => {
                        name.set(String::new());
                        refresh += 1;
                        show_toast("Passkey added", ToastLevel::Success);
                    }
                    Err(e) => error.set(Some(e)),
                }
            }
            #[cfg(not(feature = "web"))]
            {
                let _ = label;
            }
            enrolling.set(false);
        });
    };

    if !local {
        return rsx! {};
    }

    rsx! {
        div { class: "card bg-base-200 border border-base-300 mt-6",
            div { class: "card-body",
                h2 { class: "card-title text-lg mb-1", "Passkeys" }
                p { class: "text-sm text-base-content/70 mb-4",
                    "Sign in with your fingerprint, face, or screen lock. Passkeys live on your "
                    "devices; the email code always works as a fallback."
                }

                div { class: "flex gap-2 mb-4",
                    input {
                        r#type: "text",
                        class: "input input-bordered flex-1",
                        placeholder: "Name this device (e.g. Laptop)",
                        value: "{name}",
                        oninput: move |e| name.set(e.value()),
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: enrolling(),
                        onclick: enroll,
                        if enrolling() { "Waiting for device…" } else { "Add passkey" }
                    }
                }

                if let Some(err) = error() {
                    div { class: "alert alert-error mb-4", "{err}" }
                }

                match passkeys() {
                    Some(Ok(list)) if !list.is_empty() => rsx! {
                        div { class: "space-y-2",
                            for passkey in list {
                                PasskeyRow {
                                    passkey: passkey.clone(),
                                    on_removed: move |_| refresh += 1,
                                }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        p { class: "text-sm text-base-content/50", "No passkeys yet." }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "text-sm text-error", "Failed to load passkeys: {e}" }
                    },
                    None => rsx! {
                        span { class: "loading loading-spinner loading-sm" }
                    },
                }
            }
        }
    }
}

#[component]
fn PasskeyRow(passkey: PasskeySummary, on_removed: EventHandler<()>) -> Element {
    let mut removing = use_signal(|| false);
    let id_for_click = passkey.id.clone();

    let remove = move |_| {
        if removing() {
            return;
        }
        removing.set(true);
        let id = id_for_click.clone();
        spawn(async move {
            match delete_passkey(id).await {
                Ok(()) => {
                    on_removed.call(());
                    show_toast("Passkey removed", ToastLevel::Success);
                }
                Err(e) => show_toast(format!("Could not remove passkey: {e}"), ToastLevel::Error),
            }
            removing.set(false);
        });
    };

    let label = if passkey.name.is_empty() {
        "Unnamed passkey".to_string()
    } else {
        passkey.name.clone()
    };
    let added = day(&passkey.created_at);
    let used = match &passkey.last_used_at {
        Some(at) => format!("last used {}", day(at)),
        None => "never used".to_string(),
    };

    rsx! {
        div { class: "flex items-center justify-between gap-3 p-3 rounded-lg bg-base-100 border border-base-300",
            div { class: "min-w-0",
                div { class: "font-medium truncate flex items-center gap-2",
                    "{label}"
                    if passkey.backed_up {
                        span { class: "badge badge-outline badge-xs", "synced" }
                    }
                }
                div { class: "text-xs text-base-content/60", "Added {added} · {used}" }
            }
            button {
                class: "btn btn-ghost btn-xs text-error shrink-0",
                disabled: removing(),
                onclick: remove,
                "Remove"
            }
        }
    }
}

/// The calendar day of an RFC 3339 timestamp, which is all a settings row needs.
fn day(rfc3339: &str) -> &str {
    rfc3339.get(..10).unwrap_or(rfc3339)
}
