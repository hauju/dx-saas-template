use dioxus::prelude::*;
use dioxus_free_icons::{Icon, icons::ld_icons::*};

use crate::HEADER_SVG;
use crate::routes::Route;

/// Landing page.
#[component]
pub fn Home() -> Element {
    rsx! {
        section { class: "relative overflow-hidden",
            // Ambient hero backdrop: soft azure glow + masked guideline grid.
            div { class: "landing-hero-glow" }
            div { class: "landing-hero-grid" }

            div { class: "container relative mx-auto px-4 pt-20 pb-16 max-w-4xl",
                // Hero
                div { class: "flex flex-col items-center text-center",
                    span { class: "landing-hero-rise inline-flex items-center gap-2 rounded-full border border-base-300 bg-base-200/60 px-3 py-1 text-xs font-medium text-base-content/70 mb-8",
                        Icon { icon: LdSparkles, width: 14, height: 14 }
                        "Production-ready SaaS starter"
                    }

                    img {
                        src: HEADER_SVG,
                        class: "landing-hero-rise hero-delay-1 w-full max-w-xl mb-10",
                        alt: "SaaS Template",
                    }

                    h1 { class: "landing-hero-rise hero-delay-2 text-4xl sm:text-5xl font-black tracking-tight mb-5",
                        "Build your SaaS "
                        span { class: "landing-gradient-text", "faster." }
                    }
                    p { class: "landing-hero-rise hero-delay-3 text-lg text-base-content/70 max-w-xl mb-9",
                        "A production-ready Dioxus template with authentication, billing, and everything you need to ship."
                    }

                    div { class: "landing-hero-rise hero-delay-4 flex flex-col sm:flex-row items-center gap-3",
                        Link {
                            to: Route::LoginPage { redirect_url: "/dashboard".to_string() },
                            class: "btn btn-primary btn-lg btn-strong rounded-xl gap-2",
                            "Get Started"
                            Icon { icon: LdArrowRight, width: 18, height: 18 }
                        }
                        Link {
                            to: Route::DocsPage { slug: vec!["getting-started".into(), "introduction".into()] },
                            class: "btn btn-ghost btn-lg rounded-xl gap-2",
                            Icon { icon: LdBookOpen, width: 18, height: 18 }
                            "Read the docs"
                        }
                    }
                }

                // Feature cards
                div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 w-full mt-20",
                    FeatureCard {
                        icon: rsx! { Icon { icon: LdShieldCheck, width: 22, height: 22 } },
                        title: "Authentication",
                        description: "FerrisKey OIDC + WebAuthn passkeys with email OTP fallback.",
                    }
                    FeatureCard {
                        icon: rsx! { Icon { icon: LdCode, width: 22, height: 22 } },
                        title: "Fullstack Rust",
                        description: "Dioxus 0.7 with server functions, SSR, and hydration.",
                    }
                    FeatureCard {
                        icon: rsx! { Icon { icon: LdCreditCard, width: 22, height: 22 } },
                        title: "Billing Ready",
                        description: "Polar integration for subscriptions and checkout.",
                    }
                }
            }
        }
    }
}

#[component]
fn FeatureCard(icon: Element, title: &'static str, description: &'static str) -> Element {
    rsx! {
        div { class: "card card-elevated card-hover bg-base-200 h-full",
            div { class: "card-body gap-3",
                span { class: "icon-animate inline-flex items-center justify-center w-11 h-11 rounded-xl bg-primary/10 text-primary",
                    {icon}
                }
                h3 { class: "card-title text-lg", "{title}" }
                p { class: "text-base-content/60 text-sm leading-relaxed", "{description}" }
            }
        }
    }
}
