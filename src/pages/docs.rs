use dioxus::prelude::*;
use dioxus_docs_kit::{
    DocsConfig, DocsContext, DocsLayout, DocsPageContent, DocsRegistry, SearchButton,
    use_docs_providers,
};
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::ld_icons::LdMenu;
use std::sync::LazyLock;

use crate::routes::Route;

// ============================================================================
// Documentation Registry
// ============================================================================

dioxus_docs_kit::doc_content_map!();

static DOCS: LazyLock<DocsRegistry> = LazyLock::new(|| {
    DocsConfig::new(include_str!("../../docs/_nav.json"), doc_content_map())
        .with_default_path("getting-started/introduction")
        .build()
});

// ============================================================================
// Docs Layout
// ============================================================================

/// Layout wrapper that wires DocsContext + DocsRegistry into DocsLayout.
#[component]
pub fn DocsShell() -> Element {
    let nav = use_navigator();
    let route = use_route::<Route>();

    let current_path = use_memo(move || match route.clone() {
        Route::DocsPage { slug } => slug.join("/"),
        _ => String::new(),
    });

    let docs_ctx = DocsContext {
        current_path: current_path.into(),
        base_path: "/docs".into(),
        navigate: Callback::new(move |path: String| {
            let slug: Vec<String> = path.split('/').map(String::from).collect();
            nav.push(Route::DocsPage { slug });
        }),
    };

    let providers = use_docs_providers(&DOCS, docs_ctx);
    let search_open = providers.search_open;
    let mut drawer_open = providers.drawer_open;

    rsx! {
        DocsLayout {
            header: rsx! {
                div { class: "navbar bg-base-200 border-b border-base-300 px-4 lg:px-8",
                    div { class: "flex-1 gap-2",
                        button {
                            class: "btn btn-ghost btn-sm btn-square lg:hidden docs-menu-btn",
                            onclick: move |_| drawer_open.toggle(),
                            Icon { class: "size-5", icon: LdMenu }
                        }
                        Link {
                            to: Route::Home {},
                            class: "text-xl font-semibold tracking-tight hover:opacity-80 transition-opacity",
                            "SaaS Template"
                        }
                    }
                    div { class: "flex-none flex items-center gap-1",
                        ul { class: "menu menu-horizontal gap-1 hidden lg:flex",
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
                        }
                        SearchButton { search_open }
                    }
                }
            },
            Outlet::<Route> {}
        }
    }
}

// ============================================================================
// Docs Page
// ============================================================================

/// Renders a documentation page based on the URL slug.
#[component]
pub fn DocsPage(slug: Vec<String>) -> Element {
    rsx! {
        DocsPageContent { path: slug.join("/") }
    }
}
