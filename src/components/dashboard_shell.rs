use dioxus::prelude::*;
use dioxus_free_icons::{Icon, icons::ld_icons::*};

use crate::UserAuthState;
use crate::components::theme_toggle::ThemeToggle;
use crate::routes::Route;

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
                span { class: "loading loading-spinner loading-lg text-primary" }
            }
        },
        UserAuthState::NotAuthenticated => rsx! {},
        UserAuthState::Authenticated(user) => {
            let username = user.username.clone();
            let email = user.email.clone();
            let avatar_url = user.avatar_url.clone();
            rsx! {
                div { class: "drawer lg:drawer-open admin-shell",
                    input {
                        id: "dashboard-drawer",
                        r#type: "checkbox",
                        class: "drawer-toggle",
                    }

                    // Main content
                    div { class: "drawer-content flex flex-col",
                        // Top bar (mobile drawer toggle)
                        div { class: "navbar glass-panel border-b border-base-300 lg:hidden",
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
                                span { class: "inline-flex items-center gap-2 text-lg font-semibold tracking-tight",
                                    span { class: "inline-flex items-center justify-center w-7 h-7 rounded-lg bg-primary/10 text-primary",
                                        Icon { icon: LdLayers, width: 15, height: 15 }
                                    }
                                    "SaaS Template"
                                }
                            }
                        }

                        // Page content
                        div { class: "flex-1 p-4 lg:p-8 animate-fade-up",
                            Outlet::<Route> {}
                        }
                    }

                    // Sidebar
                    div { class: "drawer-side z-40",
                        label {
                            r#for: "dashboard-drawer",
                            class: "drawer-overlay",
                        }
                        aside { class: "border-r border-base-300 w-64 min-h-full flex flex-col",
                            // Logo / brand
                            div { class: "p-4 border-b border-base-300",
                                Link {
                                    to: Route::Home {},
                                    class: "inline-flex items-center gap-2 text-xl font-semibold tracking-tight",
                                    span { class: "inline-flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10 text-primary",
                                        Icon { icon: LdLayers, width: 17, height: 17 }
                                    }
                                    "SaaS Template"
                                }
                            }

                            // Navigation
                            nav { class: "flex-1 flex flex-col gap-1 p-4",
                                NavItem {
                                    to: Route::Dashboard {},
                                    icon: rsx! { Icon { icon: LdLayoutDashboard, width: 18, height: 18 } },
                                    label: "Dashboard",
                                }
                                NavItem {
                                    to: Route::Settings {},
                                    icon: rsx! { Icon { icon: LdSettings, width: 18, height: 18 } },
                                    label: "Settings",
                                }
                            }

                            // User menu at bottom
                            div { class: "p-3 border-t border-base-300",
                                UserMenu { username, email, avatar_url }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Sidebar navigation link with icon + active-route highlighting.
#[component]
fn NavItem(to: Route, icon: Element, label: &'static str) -> Element {
    rsx! {
        Link {
            to,
            class: "nav-link flex items-center text-sm font-medium text-base-content/70",
            active_class: "active",
            {icon}
            "{label}"
        }
    }
}

/// User dropdown at the foot of the sidebar: avatar + identity trigger opening a
/// menu with Settings and Logout.
#[component]
fn UserMenu(username: String, email: String, avatar_url: Option<String>) -> Element {
    let initial = username
        .chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    rsx! {
        div { class: "dropdown dropdown-top w-full",
            // Trigger
            div {
                tabindex: 0,
                role: "button",
                class: "btn btn-ghost w-full justify-start gap-3 px-2 h-auto py-2 rounded-xl",
                if let Some(url) = avatar_url.clone() {
                    img {
                        src: "{url}",
                        alt: "Avatar",
                        class: "w-8 h-8 rounded-full shrink-0 object-cover",
                    }
                } else {
                    div { class: "w-8 h-8 rounded-full bg-primary/15 text-primary flex items-center justify-center text-xs font-semibold shrink-0",
                        "{initial}"
                    }
                }
                div { class: "min-w-0 flex-1 text-left",
                    div { class: "text-sm font-medium truncate", "{username}" }
                    div { class: "text-xs text-base-content/50 truncate", "{email}" }
                }
                Icon {
                    icon: LdChevronUp,
                    width: 16,
                    height: 16,
                    class: "shrink-0 opacity-50",
                }
            }
            // Menu
            ul {
                tabindex: 0,
                class: "dropdown-content menu bg-base-100 rounded-box w-full p-2 shadow-lg border border-base-300 mb-2",
                li {
                    Link {
                        to: Route::Settings {},
                        Icon { icon: LdSettings, width: 16, height: 16 }
                        "Settings"
                    }
                }
                li {
                    ThemeToggle {}
                }
                div { class: "divider my-0" }
                li {
                    button {
                        onclick: move |_| {
                            // Full-page POST + reload: flushes the session server-side
                            // and drops all client auth state. CSRF passes (same origin).
                            let _ = document::eval(
                                "fetch('/auth/logout', { method: 'POST' })\
                                 .finally(function () { window.location.href = '/'; });",
                            );
                        },
                        Icon { icon: LdLogOut, width: 16, height: 16 }
                        "Logout"
                    }
                }
            }
        }
    }
}
