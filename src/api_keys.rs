//! API key management: server functions + a Settings card to mint/list/revoke
//! `oat_` keys. The plaintext token is returned once and shown to the user; only
//! its hash is stored server-side.

use dioxus::prelude::*;

use crate::components::toast::{ToastLevel, show_toast};
use crate::models::api_key::{ApiKeyInfo, NewApiKey};

// ============================================================================
// Server functions
// ============================================================================

#[post("/api/keys/list", session: auth::UserSession)]
pub async fn list_api_keys() -> Result<Vec<ApiKeyInfo>, ServerFnError> {
    let data = session
        .data()
        .map_err(|_| ServerFnError::new("Not logged in"))?;
    let state = crate::server::state::AppState::global();
    let user_id = bson::oid::ObjectId::parse_str(&data.id)
        .map_err(|e| ServerFnError::new(format!("invalid user id: {e}")))?;
    let keys = crate::server::api_key::list(&state.db, user_id).await?;
    Ok(keys.into_iter().map(ApiKeyInfo::from).collect())
}

#[post("/api/keys/create", session: auth::UserSession)]
pub async fn create_api_key(name: String) -> Result<NewApiKey, ServerFnError> {
    let data = session
        .data()
        .map_err(|_| ServerFnError::new("Not logged in"))?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ServerFnError::new("Name must be 1–64 characters"));
    }
    let state = crate::server::state::AppState::global();
    let user_id = bson::oid::ObjectId::parse_str(&data.id)
        .map_err(|e| ServerFnError::new(format!("invalid user id: {e}")))?;
    let (token, entity) = crate::server::api_key::create(&state.db, user_id, name).await?;
    Ok(NewApiKey {
        token,
        info: entity.into(),
    })
}

#[post("/api/keys/revoke", session: auth::UserSession)]
pub async fn revoke_api_key(id: String) -> Result<(), ServerFnError> {
    let data = session
        .data()
        .map_err(|_| ServerFnError::new("Not logged in"))?;
    let state = crate::server::state::AppState::global();
    let user_id = bson::oid::ObjectId::parse_str(&data.id)
        .map_err(|e| ServerFnError::new(format!("invalid user id: {e}")))?;
    let key_id = bson::oid::ObjectId::parse_str(&id)
        .map_err(|e| ServerFnError::new(format!("invalid key id: {e}")))?;
    crate::server::api_key::revoke(&state.db, user_id, key_id).await?;
    Ok(())
}

// ============================================================================
// UI
// ============================================================================

/// Settings card to create, list, and revoke API keys.
#[component]
pub fn ApiKeysCard() -> Element {
    let mut refresh = use_signal(|| 0u32);
    let keys = use_resource(move || async move {
        refresh();
        list_api_keys().await
    });

    let mut name = use_signal(String::new);
    let mut new_token = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);
    let mut creating = use_signal(|| false);

    let create = move |_| {
        let label = name.peek().trim().to_string();
        if label.is_empty() || creating() {
            return;
        }
        creating.set(true);
        error.set(None);
        spawn(async move {
            match create_api_key(label).await {
                Ok(created) => {
                    new_token.set(Some(created.token));
                    name.set(String::new());
                    refresh += 1;
                    show_toast("New API key created — copy it now", ToastLevel::Success);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            creating.set(false);
        });
    };

    rsx! {
        div { class: "card bg-base-200 border border-base-300 mt-6",
            div { class: "card-body",
                h2 { class: "card-title text-lg mb-1", "API keys" }
                p { class: "text-sm text-base-content/70 mb-4",
                    "Authenticate the CLI, integrations, and MCP clients. Keys are shown once."
                }

                // Create row
                div { class: "flex gap-2 mb-4",
                    input {
                        r#type: "text",
                        class: "input input-bordered flex-1",
                        placeholder: "Key name (e.g. CLI)",
                        value: "{name}",
                        oninput: move |e| name.set(e.value()),
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: creating(),
                        onclick: create,
                        if creating() { "Creating…" } else { "Create" }
                    }
                }

                // Freshly minted token (shown once)
                if let Some(token) = new_token() {
                    div { class: "alert alert-success flex-col items-start gap-2 mb-4",
                        span { class: "font-semibold", "Copy your new key now — it won't be shown again:" }
                        code { class: "font-mono text-xs break-all w-full", "{token}" }
                        button {
                            class: "btn btn-xs",
                            onclick: move |_| new_token.set(None),
                            "Dismiss"
                        }
                    }
                }

                if let Some(err) = error() {
                    div { class: "alert alert-error mb-4", "{err}" }
                }

                // Existing keys
                match keys() {
                    Some(Ok(list)) if !list.is_empty() => rsx! {
                        div { class: "space-y-2",
                            for key in list {
                                ApiKeyRow {
                                    key_id: key.id.clone(),
                                    name: key.name.clone(),
                                    prefix: key.prefix.clone(),
                                    created_at: key.created_at.clone(),
                                    on_revoked: move |_| refresh += 1,
                                }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        p { class: "text-sm text-base-content/50", "No API keys yet." }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "text-sm text-error", "Failed to load keys: {e}" }
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
fn ApiKeyRow(
    key_id: String,
    name: String,
    prefix: String,
    created_at: String,
    on_revoked: EventHandler<()>,
) -> Element {
    let mut revoking = use_signal(|| false);
    let id_for_click = key_id.clone();

    let revoke = move |_| {
        if revoking() {
            return;
        }
        revoking.set(true);
        let id = id_for_click.clone();
        spawn(async move {
            if revoke_api_key(id).await.is_ok() {
                on_revoked.call(());
                show_toast("API key revoked", ToastLevel::Success);
            }
            revoking.set(false);
        });
    };

    rsx! {
        div { class: "flex items-center justify-between gap-3 p-3 rounded-lg bg-base-100 border border-base-300",
            div { class: "min-w-0",
                div { class: "font-medium truncate", "{name}" }
                div { class: "text-xs text-base-content/60 font-mono", "{prefix}…" }
            }
            div { class: "flex items-center gap-3 shrink-0",
                span { class: "text-xs text-base-content/50", "{created_at}" }
                button {
                    class: "btn btn-ghost btn-xs text-error",
                    disabled: revoking(),
                    onclick: revoke,
                    "Revoke"
                }
            }
        }
    }
}
