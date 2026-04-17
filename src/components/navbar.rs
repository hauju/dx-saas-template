use dioxus::prelude::*;

use crate::routes::Route;
use crate::UserAuthState;

/// Public navbar with login/signup buttons.
#[component]
pub fn Navbar() -> Element {
    let user_auth = use_context::<Signal<UserAuthState>>();

    rsx! {
        div { class: "navbar bg-base-200 border-b border-base-300 px-4 lg:px-8",
            div { class: "flex-1",
                Link {
                    to: Route::Home {},
                    class: "text-xl font-semibold tracking-tight hover:opacity-80 transition-opacity",
                    "SaaS Template"
                }
            }
            div { class: "flex-none",
                ul { class: "menu menu-horizontal gap-1 items-center",
                    li {
                        Link {
                            to: Route::Home {},
                            class: "btn btn-ghost btn-sm rounded-lg font-medium",
                            "Home"
                        }
                    }
                    li {
                        Link {
                            to: Route::DocsPage { slug: vec!["getting-started".into(), "introduction".into()] },
                            class: "btn btn-ghost btn-sm rounded-lg font-medium",
                            "Docs"
                        }
                    }
                    match &*user_auth.read() {
                        UserAuthState::Authenticated(_) => rsx! {
                            li {
                                Link {
                                    to: Route::Dashboard {},
                                    class: "btn btn-primary btn-sm rounded-lg font-medium",
                                    "Dashboard"
                                }
                            }
                        },
                        _ => rsx! {
                            li {
                                Link {
                                    to: Route::LoginPage { redirect_url: "/dashboard".to_string() },
                                    class: "btn btn-primary btn-sm rounded-lg font-medium",
                                    "Sign In"
                                }
                            }
                        },
                    }
                }
            }
        }

        main { class: "min-h-screen bg-base-100",
            Outlet::<Route> {}
        }
    }
}
