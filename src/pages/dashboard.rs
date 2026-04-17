use dioxus::prelude::*;

use crate::UserAuthState;

/// Dashboard page — main authenticated landing page.
#[component]
pub fn Dashboard() -> Element {
    let user_auth = use_context::<Signal<UserAuthState>>();

    let username = match &*user_auth.read() {
        UserAuthState::Authenticated(data) => data.username.clone(),
        _ => String::new(),
    };

    rsx! {
        div { class: "max-w-4xl",
            h1 { class: "text-3xl font-bold mb-2", "Dashboard" }
            p { class: "text-base-content/70 mb-8",
                "Welcome back, {username}!"
            }

            // Placeholder cards
            div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4",
                StatCard { title: "Projects", value: "0" }
                StatCard { title: "API Calls", value: "0" }
                StatCard { title: "Storage", value: "0 MB" }
            }
        }
    }
}

#[component]
fn StatCard(title: &'static str, value: &'static str) -> Element {
    rsx! {
        div { class: "card bg-base-200 border border-base-300",
            div { class: "card-body",
                div { class: "text-sm text-base-content/60", "{title}" }
                div { class: "text-2xl font-bold mt-1", "{value}" }
            }
        }
    }
}
