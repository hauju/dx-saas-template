use dioxus::prelude::*;

use crate::components::dashboard_shell::DashboardShell;
use crate::components::navbar::Navbar;
use crate::pages::dashboard::Dashboard;
use crate::pages::docs::{DocsPage, DocsShell};
use crate::pages::home::Home;
use crate::pages::login::LoginPage;
use crate::pages::settings::Settings;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
pub enum Route {
    #[layout(Navbar)]
        #[route("/")]
        Home {},
    #[end_layout]

    #[route("/login?:redirect_url")]
    LoginPage { redirect_url: String },

    #[layout(DashboardShell)]
        #[route("/dashboard")]
        Dashboard {},
        #[route("/settings")]
        Settings {},
    #[end_layout]

    #[layout(DocsShell)]
        #[redirect("/docs", || Route::DocsPage { slug: vec!["getting-started".into(), "introduction".into()] })]
        #[route("/docs/:..slug")]
        DocsPage { slug: Vec<String> },
}
