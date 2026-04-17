use dioxus::prelude::*;

use crate::routes::Route;
use crate::UserAuthState;

/// Auth-gated dashboard layout with sidebar navigation.
/// Redirects to login when user is not authenticated.
#[component]
pub fn DashboardShell() -> Element {
    let user_auth = use_context::<Signal<UserAuthState>>();
    let nav = use_navigator();

    // Redirect to login when not authenticated
    use_effect(move || {
        if matches!(&*user_auth.read(), UserAuthState::NotAuthenticated) {
            nav.push(Route::LoginPage {
                redirect_url: "/dashboard".to_string(),
            });
        }
    });

    match &*user_auth.read() {
        UserAuthState::Loading => rsx! {
            div { class: "flex items-center justify-center min-h-screen",
                span { class: "loading loading-spinner loading-lg" }
            }
        },
        UserAuthState::NotAuthenticated => rsx! {},
        UserAuthState::Authenticated(user) => {
            let username = user.username.clone();
            let email = user.email.clone();
            rsx! {
                div { class: "drawer lg:drawer-open",
                    input {
                        id: "dashboard-drawer",
                        r#type: "checkbox",
                        class: "drawer-toggle",
                    }

                    // Main content
                    div { class: "drawer-content flex flex-col",
                        // Top bar (mobile drawer toggle)
                        div { class: "navbar bg-base-200 border-b border-base-300 lg:hidden",
                            div { class: "flex-none",
                                label {
                                    r#for: "dashboard-drawer",
                                    class: "btn btn-square btn-ghost drawer-button",
                                    svg {
                                        xmlns: "http://www.w3.org/2000/svg",
                                        fill: "none",
                                        view_box: "0 0 24 24",
                                        class: "inline-block w-5 h-5 stroke-current",
                                        path {
                                            stroke_linecap: "round",
                                            stroke_linejoin: "round",
                                            stroke_width: "2",
                                            d: "M4 6h16M4 12h16M4 18h16",
                                        }
                                    }
                                }
                            }
                            div { class: "flex-1",
                                span { class: "text-lg font-semibold", "Dashboard" }
                            }
                        }

                        // Page content
                        div { class: "flex-1 p-4 lg:p-8",
                            Outlet::<Route> {}
                        }
                    }

                    // Sidebar
                    div { class: "drawer-side z-40",
                        label {
                            r#for: "dashboard-drawer",
                            class: "drawer-overlay",
                        }
                        aside { class: "bg-base-200 border-r border-base-300 w-64 min-h-full flex flex-col",
                            // Logo / brand
                            div { class: "p-4 border-b border-base-300",
                                Link {
                                    to: Route::Home {},
                                    class: "text-xl font-semibold tracking-tight",
                                    "SaaS Template"
                                }
                            }

                            // Navigation
                            ul { class: "menu flex-1 p-4 gap-1",
                                li {
                                    Link {
                                        to: Route::Dashboard {},
                                        class: "font-medium",
                                        "Dashboard"
                                    }
                                }
                                li {
                                    Link {
                                        to: Route::Settings {},
                                        class: "font-medium",
                                        "Settings"
                                    }
                                }
                            }

                            // User info at bottom
                            div { class: "p-4 border-t border-base-300",
                                div { class: "flex items-center gap-3",
                                    div { class: "avatar placeholder",
                                        div { class: "bg-neutral text-neutral-content rounded-full w-8",
                                            span { class: "text-xs",
                                                "{username.chars().next().unwrap_or('?').to_uppercase()}"
                                            }
                                        }
                                    }
                                    div { class: "flex-1 min-w-0",
                                        div { class: "text-sm font-medium truncate", "{username}" }
                                        div { class: "text-xs opacity-60 truncate", "{email}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
