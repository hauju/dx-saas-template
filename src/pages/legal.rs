//! Terms of Service and Privacy Policy at `/legal/terms` and `/legal/privacy`,
//! the paths dx-auth's acceptance step links to. Placeholder text: replace it
//! with your own before launch, then bump `TOS_VERSION` so existing users
//! accept the new terms on their next login.

use dioxus::prelude::*;

#[component]
pub fn Terms() -> Element {
    rsx! {
        LegalPage { title: "Terms of Service", updated: "September 2026",
            p {
                "These terms govern your use of SaaS Template (the \"Service\"). By creating an "
                "account or using the Service you agree to them."
            }
            h2 { "Your account" }
            p {
                "You are responsible for the activity under your account and for keeping your "
                "sign-in methods (passkeys, email access) secure. Tell us promptly if you believe "
                "your account has been compromised."
            }
            h2 { "Acceptable use" }
            p {
                "Do not use the Service to break the law, to infringe others' rights, or to "
                "attack, overload or probe the Service or anyone else's systems."
            }
            h2 { "Subscriptions and billing" }
            p {
                "Paid plans renew automatically until cancelled. Fees are non-refundable except "
                "where the law requires otherwise. Prices may change with notice before your "
                "next renewal."
            }
            h2 { "Termination" }
            p {
                "You may close your account at any time. We may suspend or close accounts that "
                "breach these terms."
            }
            h2 { "Disclaimer and liability" }
            p {
                "The Service is provided as is. To the extent permitted by law we exclude all "
                "warranties, and our liability is limited to the amount you paid us in the "
                "twelve months before the claim."
            }
            h2 { "Changes" }
            p {
                "We may update these terms. When we do, you will be asked to accept the new "
                "version the next time you sign in."
            }
        }
    }
}

#[component]
pub fn Privacy() -> Element {
    rsx! {
        LegalPage { title: "Privacy Policy", updated: "September 2026",
            p {
                "This policy explains what SaaS Template collects, why, and what you can do "
                "about it."
            }
            h2 { "What we collect" }
            ul {
                li { "Your email address, to sign you in and to reach you about your account." }
                li {
                    "Passkey public keys, if you enroll one. The private half never leaves your "
                    "device."
                }
                li { "Subscription state from our billing provider, so we know what you can use." }
                li { "Server logs with IP addresses, kept briefly for security and abuse prevention." }
            }
            h2 { "What we do not do" }
            p { "We do not sell your data and we do not use it for advertising." }
            h2 { "Processors" }
            p {
                "Email delivery, payments and hosting are provided by third parties acting on "
                "our instructions. Each receives only what its job requires."
            }
            h2 { "Your rights" }
            p {
                "You can ask for a copy of your data, correct it, or have your account deleted. "
                "Contact us at the address on the site."
            }
            h2 { "Changes" }
            p { "We will note material changes here and, where required, ask for your consent." }
        }
    }
}

#[component]
fn LegalPage(title: &'static str, updated: &'static str, children: Element) -> Element {
    rsx! {
        div { class: "container mx-auto px-4 py-16 max-w-3xl",
            div { class: "alert alert-warning rounded-xl mb-8 text-sm",
                span {
                    "Placeholder text. Replace it with terms reviewed for your product, then "
                    "bump "
                    code { "TOS_VERSION" }
                    " so existing users accept the new version."
                }
            }
            article { class: "prose prose-invert max-w-none",
                h1 { "{title}" }
                p { class: "text-sm text-base-content/60", "Last updated: {updated}" }
                {children}
            }
        }
    }
}
