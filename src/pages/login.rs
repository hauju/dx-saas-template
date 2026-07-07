use dioxus::prelude::*;

#[cfg(feature = "web")]
use auth::UserDataRefreshTrigger;

use crate::UserAuthState;
use crate::routes::Route;

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
        div { class: "relative min-h-screen overflow-hidden flex items-center justify-center p-4",
            // Background layer — gradient mesh
            div { class: "absolute inset-0 bg-gradient-to-br from-base-100 via-base-100 to-primary/5" }
            div { class: "absolute top-20 right-20 w-[28rem] h-[28rem] bg-primary/8 rounded-full blur-[100px]" }
            div { class: "absolute bottom-40 left-10 w-80 h-80 bg-secondary/8 rounded-full blur-[80px]" }
            div { class: "absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[40rem] h-[40rem] bg-primary/5 rounded-full blur-[120px]" }

            // Back to home (subtle, floating)
            div { class: "absolute top-4 left-4 z-20",
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

            // Login card
            div { class: "relative z-10 w-full max-w-md",
                div { class: "relative rounded-2xl bg-base-200/60 backdrop-blur-xl border border-base-300/50 shadow-2xl overflow-hidden",
                    // Top accent line
                    div { class: "absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent" }

                    div { class: "p-8",
                        // Logo / brand
                        div { class: "text-center mb-6",
                            div { class: "inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-primary to-secondary text-white shadow-lg shadow-primary/25 mb-4",
                                svg {
                                    xmlns: "http://www.w3.org/2000/svg",
                                    width: "28",
                                    height: "28",
                                    view_box: "0 0 24 24",
                                    fill: "none",
                                    rect { x: "3", y: "3", width: "7", height: "9", rx: "1.5", fill: "currentColor", opacity: "0.5" }
                                    rect { x: "14", y: "3", width: "7", height: "5", rx: "1.5", fill: "currentColor" }
                                    rect { x: "14", y: "12", width: "7", height: "9", rx: "1.5", fill: "currentColor", opacity: "0.5" }
                                    rect { x: "3", y: "16", width: "7", height: "5", rx: "1.5", fill: "currentColor", opacity: "0.5" }
                                }
                            }
                            h1 { class: "text-2xl font-semibold tracking-tight", "SaaS Template" }
                            p { class: "text-sm text-base-content/60 mt-1", "Sign in or create an account" }
                        }

                        // Auth crate's LoginPage (embedded — no wrapper/header)
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
                            embed: true,
                        }

                        // Reassurance for new signups
                        p { class: "mt-6 text-center text-xs text-base-content/50",
                            "New here? Free to start \u{00b7} no credit card required."
                        }
                    }
                }
            }
        }
    }
}
