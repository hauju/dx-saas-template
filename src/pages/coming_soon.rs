use dioxus::prelude::*;
use dioxus_free_icons::{Icon, icons::ld_icons::*};

use crate::HEADER_SVG;
use crate::waitlist::WaitlistForm;

/// Pre-launch front page (`COMING_SOON=true`): the pitch and a waitlist form,
/// nothing else to click. `Home` renders it in place of the landing page.
#[component]
pub fn ComingSoon() -> Element {
    rsx! {
        section { class: "relative overflow-hidden min-h-screen flex items-center",
            div { class: "landing-hero-glow" }
            div { class: "landing-hero-grid" }

            div { class: "container relative mx-auto px-4 py-20 max-w-3xl",
                div { class: "flex flex-col items-center text-center",
                    span { class: "landing-hero-rise inline-flex items-center gap-2 rounded-full border border-base-300 bg-base-200/60 px-3 py-1 text-xs font-medium text-base-content/70 mb-8",
                        Icon { icon: LdSparkles, width: 14, height: 14 }
                        "Coming soon"
                    }

                    img {
                        src: HEADER_SVG,
                        class: "landing-hero-rise hero-delay-1 w-full max-w-lg mb-10",
                        alt: "SaaS Template",
                    }

                    h1 { class: "landing-hero-rise hero-delay-2 text-4xl sm:text-5xl font-black tracking-tight mb-5",
                        "Something "
                        span { class: "landing-gradient-text", "worth waiting for." }
                    }
                    p { class: "landing-hero-rise hero-delay-3 text-lg text-base-content/70 max-w-xl mb-9",
                        "We're putting the finishing touches on it. Leave your address and you'll be "
                        "the first to know when it opens — no other mail, nothing to unsubscribe from."
                    }

                    div { class: "landing-hero-rise hero-delay-4 w-full flex flex-col items-center",
                        WaitlistForm {}
                    }
                }
            }
        }
    }
}
