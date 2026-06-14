//! Subscription status + a gated example endpoint, demonstrating how Polar
//! webhook state drives premium access.

use dioxus::prelude::*;

use crate::models::subscription::SubscriptionInfo;

// ============================================================================
// Server functions
// ============================================================================

#[post("/api/subscription", session: auth::UserSession)]
pub async fn subscription_status() -> Result<Option<SubscriptionInfo>, ServerFnError> {
    let data = session
        .data()
        .map_err(|_| ServerFnError::new("Not logged in"))?;
    let state = crate::server::state::AppState::global();
    let user_id = bson::oid::ObjectId::parse_str(&data.id)
        .map_err(|e| ServerFnError::new(format!("invalid user id: {e}")))?;
    let user = state
        .db
        .users
        .find_one(bson::doc! { "_id": user_id })
        .await
        .map_err(|e| ServerFnError::new(format!("db error: {e}")))?;
    Ok(user.and_then(|u| u.subscription))
}

/// Example premium endpoint gated by an active subscription. Returns
/// `402 Payment Required` when the user has no active subscription.
#[post("/api/premium/ping", session: auth::UserSession)]
pub async fn premium_ping() -> Result<String, ServerFnError> {
    let data = session
        .data()
        .map_err(|_| ServerFnError::new("Not logged in"))?;
    let state = crate::server::state::AppState::global();
    let user_id = bson::oid::ObjectId::parse_str(&data.id)
        .map_err(|e| ServerFnError::new(format!("invalid user id: {e}")))?;
    let user = state
        .db
        .users
        .find_one(bson::doc! { "_id": user_id })
        .await
        .map_err(|e| ServerFnError::new(format!("db error: {e}")))?
        .ok_or_else(|| ServerFnError::new("user not found"))?;

    crate::server::billing::require_active(&user.subscription)?;
    Ok("pong — premium access confirmed".to_string())
}

// ============================================================================
// UI
// ============================================================================

/// Settings card showing subscription status with a button that exercises the
/// subscription-gated `premium_ping` endpoint.
#[component]
pub fn SubscriptionCard() -> Element {
    let status = use_resource(move || async move { subscription_status().await });
    let mut ping_result = use_signal(|| None::<String>);

    let test = move |_| {
        spawn(async move {
            match premium_ping().await {
                Ok(msg) => ping_result.set(Some(msg)),
                Err(e) => ping_result.set(Some(e.to_string())),
            }
        });
    };

    rsx! {
        div { class: "card bg-base-200 border border-base-300 mt-6",
            div { class: "card-body",
                h2 { class: "card-title text-lg mb-1", "Subscription" }
                p { class: "text-sm text-base-content/70 mb-4",
                    "Synced from Polar billing webhooks."
                }

                match status() {
                    Some(Ok(Some(sub))) => {
                        let badge_class = if sub.is_active() {
                            "badge badge-success"
                        } else {
                            "badge badge-ghost"
                        };
                        let tier = sub.tier.clone();
                        rsx! {
                            div { class: "flex items-center gap-2 mb-4",
                                span { class: "{badge_class}", "{sub.status}" }
                                if let Some(tier) = tier {
                                    span { class: "text-sm text-base-content/70", "{tier}" }
                                }
                            }
                        }
                    }
                    Some(Ok(None)) => rsx! {
                        p { class: "text-sm text-base-content/60 mb-4", "No active subscription." }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "text-sm text-error mb-4", "{e}" }
                    },
                    None => rsx! {
                        span { class: "loading loading-spinner loading-sm" }
                    },
                }

                button { class: "btn btn-sm btn-outline w-fit", onclick: test, "Test premium access" }
                if let Some(res) = ping_result() {
                    p { class: "text-sm mt-2", "{res}" }
                }
            }
        }
    }
}
