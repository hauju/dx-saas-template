# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A fullstack SaaS template built with Dioxus 0.7 (Rust), using MongoDB, Redis, Zitadel (OIDC auth), Polar (billing), and SMTP email. The app compiles into two binaries via Cargo feature flags: a server (`server` feature) and a WASM client (`web` feature).

## Commands

```sh
# Start infrastructure (MongoDB with replica set, Redis/Valkey, Mailpit)
docker compose up -d
# or: just init

# Development server (auto-reloads on changes)
dx serve --addr 0.0.0.0
# or: just serve

# Build Tailwind CSS manually
bunx @tailwindcss/cli -i tailwind.css -o ./assets/tailwind.css
# or: just tw

# Lint / format
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
# or: just check

# Check for unused dependencies
cargo machete

# Build for production
dx build --release --platform web
```

There are no tests in the project yet. The `dx` CLI is installed via `curl -sSL http://dioxus.dev/install.sh | sh`.

### CI Checks (must pass before merge)

```sh
cargo fmt --all --check                                          # Formatting
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Linting
cargo machete                                                     # Unused dependency detection
cargo test --workspace --exclude dx-saas-template                 # Unit tests (crates only)
```

Tailwind must be pre-compiled for clippy/CI (since `dx serve` isn't running):

```sh
bun install --frozen-lockfile
bunx @tailwindcss/cli -i tailwind.css -o assets/tailwind.css
```

## Architecture

### Feature-Gated Compilation

The binary is split by Cargo features. Code gated with `#[cfg(feature = "server")]` only compiles for the server; `#[cfg(feature = "web")]` or `#[cfg(not(feature = "server"))]` only for the WASM client. The `server` feature pulls in MongoDB, Axum, tower-sessions, etc. The `web` feature pulls in gloo/wasm bindings. The `web` feature must propagate to sub-crates (e.g., `auth/web`) for their UI components and CSS classes to be included in Tailwind scanning.

### Source Layout

- **`src/main.rs`** — Dual entry point. Server builds an Axum router with session layer, auth routes, and Dioxus SSR. Client calls `dioxus::launch(App)`. The `App` component provides auth state context and routes.
- **`src/routes.rs`** — `Route` enum (derives `Routable`). Three layouts: `Navbar` for public pages, `DashboardShell` for authenticated pages, `DocsShell` for documentation pages.
- **`src/pages/`** — Page components: `Home`, `LoginPage`, `Dashboard`, `Settings`, `DocsPage`.
- **`src/components/`** — Shared UI: `Navbar`, `DashboardShell`, `ToastProvider`/`ToastManager`.
- **`src/models/`** — Shared types (`LoggedInData`, `AppError`). `UserEntity` is server-only.
- **`src/server/`** — Server-only: `AppState` (global singleton via `OnceLock`), `Config`/`Secrets`, `Database` (MongoDB), `AppAuthUserStore`/`AppEmailSender` (trait implementations).

### Workspace Crates (`crates/`)

All crates are decoupled from the main app via traits and config structs:

- **`auth`** — Zitadel OIDC + Session API v2 integration, session management (`UserSession` extractor), rate limiting, login page component. Has `server` and `web` feature flags. Defines `AuthUserStore` and `AuthEmailSender` traits that the main app implements.
- **`crypto`** — Argon2 hashing, AES-256-GCM encryption, token/OTP generation.
- **`smtp`** — Email sending via `lettre` with sync and async clients, attachment support.
- **`polar`** — Polar.sh billing API: customers, subscriptions, checkout, orders, webhook verification.

### Documentation Site (`dioxus-docs-kit`)

The `/docs` route serves a documentation site powered by `dioxus-docs-kit` v0.4. Content is written in MDX files under `docs/` and embedded at compile time.

- **`build.rs`** — Calls `dioxus_docs_kit_build::generate_content_map("docs/_nav.json")` to generate the content map macro.
- **`docs/_nav.json`** — Navigation structure (tabs, groups, pages). Pages reference MDX file paths without the `.mdx` extension.
- **`docs/**/*.mdx`** — MDX documentation pages with frontmatter (`title`, `description`, `sidebarTitle`).
- **`safelist-docs-kit.html`** — Tailwind CSS safelist for `dioxus-docs-kit` classes (referenced via `@source` in `tailwind.css`). Since the crate is a cargo dependency, Tailwind cannot scan classes inside `~/.cargo` — this safelist makes them available.
- **`src/pages/docs.rs`** — `DocsShell` layout (wires `DocsContext` + `DocsRegistry` into `DocsLayout`) and `DocsPage` component (renders `DocsPageContent`).

To add a new docs page: create an `.mdx` file in `docs/`, add its path to the appropriate group in `docs/_nav.json`, then rebuild.

### Key Patterns

- **Global state**: `AppState::global()` via `OnceLock`, also available as an Axum extractor.
- **Auth flow**: Zitadel OIDC → session cookie (tower-sessions + Redis) → `UserSession` extractor on server functions.
- **Client auth state**: `UserAuthState` enum provided via context. `use_server_future` fetches `/api/me` on load; a `UserDataRefreshTrigger` signal re-fetches on demand.
- **Server functions**: Use `#[post("/api/...")]` with optional `session: auth::UserSession` parameter.
- **Error handling**: `AppError` enum maps to HTTP status codes and converts to `ServerFnError` for RPC.
- **Database**: MongoDB database named `dx_saas`, single `users` collection with unique indexes on `sub` and `email`.
- **Axum route params**: Use curly braces `"/api/{id}"` not colon `"/api/:id"` in Axum 0.8+ routes (colon causes runtime panic).
- **Crate fast-check**: Use `cargo check -p crate-name` for fast feedback when editing workspace crates before a full build.

### Infrastructure

- **MongoDB**: Runs as replica set (`rs0`) for transaction support. Port 27017.
- **Redis (Valkey)**: Session store. Port 6379.
- **Mailpit**: Local SMTP testing. SMTP on 1025, Web UI on 8025.

### Docker

The `Dockerfile` builds a two-stage image: compiles with `dx build --release --platform web` in a Rust builder, then copies the `dist/` output into a slim Debian runtime. The app listens on port 8080. Docs and build.rs assets must be present at build time.

### Environment Variables

Copy `.env.example` to `.env`. Key variables: `DATABASE_URL`, `REDIS_URL`, `BASE_URL`, `SESSION_SECRET` (hex, 64+ bytes), `ZITADEL_DOMAIN`, SMTP settings, optional Polar billing keys, optional `SENTRY_DSN` + `ENVIRONMENT` (requires `--features sentry`).

### Styling

TailwindCSS 4 + DaisyUI 5 (dark theme default). Source scanning is configured in `tailwind.css`. Dioxus 0.7+ auto-detects `tailwind.css` and runs Tailwind during `dx serve`. Icons via `dioxus-free-icons` with Lucide icon set.

---

## Dioxus 0.7 Reference

You are an expert [0.7 Dioxus](https://dioxuslabs.com/learn/0.7) assistant. Dioxus 0.7 changes every api in dioxus. Only use this up to date documentation. `cx`, `Scope`, and `use_state` are gone.

### Launching

```rust
use dioxus::prelude::*;

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! { "Hello, Dioxus!" }
}
```

### RSX

```rust
rsx! {
    div {
        class: "container",
        color: "red",
        width: if condition { "100%" },
        "Hello, Dioxus!"
    }
    for i in 0..5 {
        div { "{i}" }
    }
    if condition {
        div { "Condition is true!" }
    }
    {children}
    {(0..5).map(|i| rsx! { span { "Item {i}" } })}
}
```

### Assets

```rust
rsx! {
    img { src: asset!("/assets/image.png"), alt: "An image" }
    document::Stylesheet { href: asset!("/assets/styles.css") }
}
```

### Components & Props

- Annotate with `#[component]`, function name starts with capital letter.
- Props must be owned (`String` not `&str`), implement `PartialEq` + `Clone`.
- Wrap in `ReadOnlySignal` for reactive props.
- Re-renders when props change or internal reactive state updates.

### State

```rust
// Local state
let mut count = use_signal(|| 0);
let doubled = use_memo(move || count() * 2);

// Read: count() clones, count.read() borrows
// Write: *count.write() += 1  or  count.with_mut(|c| *c += 1)

// Context API
use_context_provider(|| Signal::new(value));
let ctx = use_context::<Signal<T>>();
```

### Async

```rust
let data = use_resource(move || async move { fetch().await });
match data() {
    Some(value) => rsx! { "{value}" },
    None => rsx! { "Loading..." },
}
```

### Routing

```rust
#[derive(Routable, Clone, PartialEq)]
enum Route {
    #[layout(NavBar)]
        #[route("/")]
        Home {},
        #[route("/blog/:id")]
        BlogPost { id: i32 },
}
```

### Server Functions

```rust
#[post("/api/double/:path/&query")]
async fn double_server(number: i32, path: String, query: i32) -> Result<i32, ServerFnError> {
    Ok(number * 2)
}
```

Server functions with `#[get]` cannot have body parameters beyond state/session — use `#[post]` when parameters are needed. Use `#[get("/path")]` only for plain endpoints with no params (like health checks or llms.txt).

Route components must be imported with `use` in the file where the `Route` enum is defined (`routes.rs`), so the Routable derive macro can find them.

### Hydration

- Use `use_server_future` instead of `use_resource` for SSR data to avoid hydration mismatch.
- Browser-only APIs (e.g. `localStorage`) must go in `use_effect`.
