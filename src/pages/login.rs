use dioxus::prelude::*;

#[cfg(feature = "web")]
use auth::UserDataRefreshTrigger;

use crate::routes::Route;
use crate::UserAuthState;

/// Login page that wraps the auth crate's LoginPage component.
#[component]
pub fn LoginPage(redirect_url: String) -> Element {
    let user_auth = use_context::<Signal<UserAuthState>>();
    let nav = use_navigator();

    // If already authenticated, redirect to dashboard
    use_effect(move || {
        if matches!(&*user_auth.read(), UserAuthState::Authenticated(_)) {
            nav.push(Route::Dashboard {});
        }
    });

    rsx! {
        div { class: "min-h-screen bg-base-100 flex items-center justify-center p-4",
            div { class: "w-full max-w-md",
                // Back to home link
                div { class: "mb-6",
                    Link {
                        to: Route::Home {},
                        class: "btn btn-ghost btn-sm gap-2",
                        svg {
                            xmlns: "http://www.w3.org/2000/svg",
                            class: "h-4 w-4",
                            fill: "none",
                            view_box: "0 0 24 24",
                            stroke: "currentColor",
                            path {
                                stroke_linecap: "round",
                                stroke_linejoin: "round",
                                stroke_width: "2",
                                d: "M15 19l-7-7 7-7",
                            }
                        }
                        "Back"
                    }
                }

                auth::LoginPage {
                    redirect_url: redirect_url.clone(),
                    on_success: move |_url: String| {
                        #[cfg(feature = "web")]
                        {
                            // Bump the refresh trigger so App re-fetches login data
                            let mut trigger = consume_context::<Signal<UserDataRefreshTrigger>>();
                            trigger.write().0 += 1;
                        }
                    },
                }
            }
        }
    }
}
