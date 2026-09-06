use dioxus::prelude::*;

use crate::UserAuthState;
use crate::api_keys::ApiKeysCard;
use crate::passkeys::PasskeysCard;
use crate::subscription::SubscriptionCard;

/// Settings page — user account settings.
#[component]
pub fn Settings() -> Element {
    let user_auth = use_context::<Memo<UserAuthState>>();

    let (email, username) = match &*user_auth.read() {
        UserAuthState::Authenticated(data) => (data.email.clone(), data.username.clone()),
        _ => (String::new(), String::new()),
    };

    rsx! {
        div { class: "max-w-2xl",
            h1 { class: "text-3xl font-bold mb-2", "Settings" }
            p { class: "text-base-content/70 mb-8", "Manage your account settings." }

            // Profile section
            div { class: "card bg-base-200 border border-base-300",
                div { class: "card-body",
                    h2 { class: "card-title text-lg mb-4", "Profile" }

                    div { class: "space-y-4",
                        div {
                            label { class: "label", span { class: "label-text", "Username" } }
                            input {
                                r#type: "text",
                                class: "input input-bordered w-full",
                                value: "{username}",
                                disabled: true,
                            }
                        }
                        div {
                            label { class: "label", span { class: "label-text", "Email" } }
                            input {
                                r#type: "email",
                                class: "input input-bordered w-full",
                                value: "{email}",
                                disabled: true,
                            }
                        }
                    }
                }
            }

            PasskeysCard {}
            ApiKeysCard {}
            SubscriptionCard {}
        }
    }
}
