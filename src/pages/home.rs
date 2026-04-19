use dioxus::prelude::*;

use crate::HEADER_SVG;
use crate::routes::Route;

/// Landing page.
#[component]
pub fn Home() -> Element {
    rsx! {
        div { class: "container mx-auto px-4 py-12 max-w-4xl",
            // Hero
            div { class: "flex flex-col items-center text-center mb-16",
                img {
                    src: HEADER_SVG,
                    class: "w-full max-w-2xl mb-12",
                    alt: "Logo",
                }

                h1 { class: "text-4xl font-bold mb-4",
                    "Build your SaaS faster"
                }
                p { class: "text-lg text-base-content/70 max-w-xl mb-8",
                    "A production-ready Dioxus template with authentication, billing, and everything you need to ship."
                }

                Link {
                    to: Route::LoginPage { redirect_url: "/dashboard".to_string() },
                    class: "btn btn-primary btn-lg",
                    "Get Started"
                }
            }

            // Feature cards
            div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 w-full max-w-3xl mx-auto",
                FeatureCard {
                    title: "Authentication",
                    description: "Zitadel OIDC + WebAuthn passkeys with email OTP fallback.",
                }
                FeatureCard {
                    title: "Fullstack Rust",
                    description: "Dioxus 0.7 with server functions, SSR, and hydration.",
                }
                FeatureCard {
                    title: "Billing Ready",
                    description: "Polar integration for subscriptions and checkout.",
                }
            }
        }
    }
}

#[component]
fn FeatureCard(title: &'static str, description: &'static str) -> Element {
    rsx! {
        div { class: "card bg-base-200 border border-base-300",
            div { class: "card-body",
                h3 { class: "card-title text-lg", "{title}" }
                p { class: "text-base-content/70 text-sm", "{description}" }
            }
        }
    }
}
