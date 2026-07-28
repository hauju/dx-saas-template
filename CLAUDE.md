# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A fullstack SaaS template built with Dioxus 0.7 (Rust), using PostgreSQL, FerrisKey (OIDC auth), Polar (billing), and SMTP email. The app compiles into two binaries via Cargo feature flags: a server (`server` feature) and a WASM client (`web` feature).

## Commands

```sh
# Start infrastructure (PostgreSQL, Mailpit)
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

# Regenerate compile-time SQL metadata after changing any query or migration
cargo sqlx prepare -- --no-default-features --features server

# Build for production
dx build --release --platform web
```

Tests live in the workspace crates and in `src/server/{security,oauth}.rs`; both are run by CI (see below). The `dx` CLI is installed via `curl -sSL http://dioxus.dev/install.sh | sh`, and `sqlx-cli` (`cargo install sqlx-cli --no-default-features --features rustls,postgres`) is needed only to regenerate `.sqlx/`.

### CI Checks (must pass before merge)

```sh
cargo fmt --all --check                                          # Formatting
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Linting
cargo machete                                                     # Unused dependency detection
cargo test --workspace --exclude dx-saas-template                 # Unit tests (workspace crates)
cargo test -p dx-saas-template --no-default-features --features server  # Unit tests (app crate)
```

Tailwind must be pre-compiled for clippy/CI (since `dx serve` isn't running):

```sh
bun install --frozen-lockfile
bunx @tailwindcss/cli -i tailwind.css -o assets/tailwind.css
```

## Architecture

### Feature-Gated Compilation

The binary is split by Cargo features. Code gated with `#[cfg(feature = "server")]` only compiles for the server; `#[cfg(feature = "web")]` or `#[cfg(not(feature = "server"))]` only for the WASM client. The `server` feature pulls in sqlx/PostgreSQL, Axum, tower-sessions, etc. The `web` feature pulls in gloo/wasm bindings. The `web` feature must propagate to sub-crates (e.g., `auth/web`) for their UI components and CSS classes to be included in Tailwind scanning.

### Source Layout

- **`src/main.rs`** — Dual entry point. Server builds an Axum router with session layer, auth routes, and Dioxus SSR. Client calls `dioxus::launch(App)`. The `App` component provides auth state context and routes.
- **`src/routes.rs`** — `Route` enum (derives `Routable`). Three layouts: `Navbar` for public pages, `DashboardShell` for authenticated pages, `DocsShell` for documentation pages.
- **`src/pages/`** — Page components: `Home`, `LoginPage`, `Dashboard`, `Settings`, `DocsPage`.
- **`src/components/`** — Shared UI: `Navbar`, `DashboardShell`, `ToastProvider`/`ToastManager`.
- **`src/models/`** — Shared types (`LoggedInData`, `AppError`, `ApiKeyInfo`/`NewApiKey`, `SubscriptionInfo`). `UserEntity` and `ApiKeyEntity` are server-only.
- **`src/server/`** — Server-only: `AppState` (global singleton via `OnceLock`, also holds the shared `JwksCache`), `Config`/`Secrets`, `Database` (PostgreSQL pool), `user` (row → `UserEntity` read helpers), `AppAuthUserStore`/`AppEmailSender` (trait implementations). Also: `security` (response headers, redacted request spans, reusable `IpRateLimiter`), `api_key`/`api_auth` (opaque `oat_` key store + dual-auth `ApiAuth` extractor), `oauth` (self-hosted OAuth 2.1 AS for MCP), `mcp` (`rmcp` Streamable-HTTP MCP server), `billing` (Polar webhook + subscription gating).
- **`src/api_keys.rs`** / **`src/subscription.rs`** — Dual-target modules with server functions + Settings UI cards for API-key management and subscription status.
- **`migrations/`** — Numbered SQL migrations (`0001_users.sql`, …), embedded at compile time by `sqlx::migrate!` and applied on boot.

### Workspace Crates (`crates/`)

All crates are decoupled from the main app via traits and config structs:

- **`auth`** — FerrisKey OIDC integration with custom login UI (passkey, password, email-OTP), JWKS validation, CAPTCHA-gated registration, session management (`UserSession` extractor), rate limiting. Has `server` and `web` feature flags. Defines `AuthUserStore` and `AuthEmailSender` traits that the main app implements.
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
- **Auth flow**: FerrisKey OIDC (auth code + PKCE) → session cookie (tower-sessions + PostgreSQL) → `UserSession` extractor on server functions. Supports passkey, password, and email-OTP login paths.
- **Client auth state**: `UserAuthState` enum provided via context. `use_server_future` fetches `/api/me` on load; a `UserDataRefreshTrigger` signal re-fetches on demand.
- **Server functions**: Use `#[post("/api/...")]` with optional `session: auth::UserSession` parameter.
- **Error handling**: `AppError` enum maps to HTTP status codes and converts to `ServerFnError` for RPC.
- **Database**: PostgreSQL via `sqlx`. Schema lives in `migrations/`, embedded with `sqlx::migrate!` and applied on boot in `Database::new`. Tables: `users` (unique `sub`/`email`, JSONB `subscription`), `api_keys` (prefix + owner indexes), `oauth_clients` (unique `client_id`), `oauth_codes` (unique `code`, expiry checked on consumption, abandoned rows swept on insert), `rate_limits` (see below). Queries live in `src/server/user.rs` / `api_key.rs` / `oauth/store.rs` rather than inline at call sites. Adding a table means adding a numbered `.sql` file to `migrations/`.
- **Migrations are immutable once applied**: `sqlx` records a checksum per migration, so editing a file that has already run — even just a comment — makes the next boot fail with "was previously applied but has been modified". Always add a new numbered migration instead. (Rebuilding a local database is the fast way out during development.)
- **Compile-time-checked SQL**: queries use the `sqlx::query!` / `query_as!` macros, so column names, types, and nullability are verified against the schema at build time. Metadata is committed in `.sqlx/`, and `.cargo/config.toml` sets `SQLX_OFFLINE=true`, so a fresh clone builds with no database running. **After changing any SQL or migration you must run `cargo sqlx prepare -- --no-default-features --features server` against a live database** (`docker compose up -d` first). Note what each check actually catches: cached entries are keyed by a hash of the SQL string, so *changing a query* without re-preparing fails the next offline build, but *changing the schema* while leaving queries untouched leaves stale entries that still match and still compile — the failure surfaces at runtime instead. The `schema` CI job covers that second case by building against a real database. Two gotchas: `tower-sessions-sqlx-store` forces sqlx's `time` feature on, and since Cargo unifies features the macros map `TIMESTAMPTZ` to `time::OffsetDateTime` unless you annotate reads as `col as "col: Ts"` (a chrono alias); and timestamps are therefore written by the database (`DEFAULT NOW()` / `NOW()` / `make_interval`) rather than bound from Rust, which also keeps the database clock authoritative across replicas.
- **API keys (M2M auth)**: `oat_` tokens, Argon2-hashed with a separate indexed prefix for lookup (`src/server/api_key.rs`). The `ApiAuth` extractor (`src/server/api_auth.rs`) accepts either `X-API-Key`/`Authorization: Bearer oat_…` or a FerrisKey JWT. Manage keys in Settings.
- **OAuth-for-MCP**: A self-hosted OAuth 2.1 authorization server (`src/server/oauth/`) — protected-resource + AS metadata (RFC 9728/8414), dynamic client registration (RFC 7591, redirect-URI allowlist is the security boundary), auth-code + PKCE S256 reusing the login session, and a token endpoint that mints `oat_` tokens. The MCP endpoint (`POST /mcp`, `src/server/mcp.rs`) is an `rmcp` 0.14 `StreamableHttpService` with tools defined via `#[tool_router]`/`#[tool]` on `McpTools`; tools authenticate via the shared `api_auth::authenticate`. An `mcp_auth_challenge` middleware does a presence-only check — no credential returns `401` + `WWW-Authenticate` pointing at the metadata (triggering OAuth discovery). Add new tools as `#[tool]` methods.
- **Billing webhooks**: `POST /webhooks/polar` (`src/server/billing.rs`) verifies the Standard Webhooks signature and syncs `SubscriptionInfo` onto the user. Gate premium features with `billing::require_active(&user.subscription)?` (maps to `402`).
- **Security middleware**: `src/server/security.rs` adds hardening headers (HSTS gated on `secure_cookies`, CSP `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, referrer policy), a query-redacted request span, and a reusable per-IP `IpRateLimiter`. The server is served with `into_make_service_with_connect_info` so per-IP limiting works.
- **Rate limiting has two backends** (`IpRateLimiter`): `per_minute` counts in-process with `governor` — used for the global 600/min backstop, where a database round-trip per request would cost more than the accuracy is worth, and where N replicas allowing N× the quota is acceptable. `shared_per_minute` counts in the `rate_limits` table (`src/server/rate_limit.rs`), so the quota holds across replicas; used on the low-volume sensitive routers (OAuth 60/min, MCP and webhooks 120/min). Auth endpoints get the same treatment through `auth::AuthRateLimitStore`, a trait the auth crate defines and `AppAuthRateLimitStore` implements, so the crate stays storage-agnostic. Both shared paths **fail open** on database errors — every route behind them needs the same database to serve a real response, so failing closed would turn a blip into an outage while denying an attacker nothing. Elapsed windows are swept every 10 minutes.
- **Graceful shutdown**: `shutdown_signal()` in `main.rs` catches Ctrl-C and SIGTERM so redeploys drain in-flight requests. Orchestrators SIGKILL after a grace period (Docker: 10s), so keep long work off the request path.
- **Health probe**: `GET /health` (`src/server/health.rs`) round-trips a query to PostgreSQL, so it reports unhealthy when the process is up but the database is not. Wired to the image's `HEALTHCHECK`.
- **Axum route params**: Use curly braces `"/api/{id}"` not colon `"/api/:id"` in Axum 0.8+ routes (colon causes runtime panic).
- **Crate fast-check**: Use `cargo check -p crate-name` for fast feedback when editing workspace crates before a full build.

### Infrastructure

- **PostgreSQL**: Port 5432. Backs application data, the session store (`tower-sessions-sqlx-store`, which manages its own `tower_sessions` schema and prunes expired rows hourly), and shared rate-limit counters.
- **Mailpit**: Local SMTP testing. SMTP on 1025, Web UI on 8025.

### Docker

The `Dockerfile` does **not** compile anything — it packages a bundle built outside Docker. CI (`.github/workflows/deploy.yml`) runs `dx bundle --web --release` and the image copies the resulting `target/dx/dx-saas-template/release/web` into a slim Debian runtime. This keeps cargo/wasm caching in CI and the runtime image small; the deploy host never compiles. Docs, `build.rs` output, and SQL migrations are embedded in the server binary at compile time, so none of them ship as files. The app listens on port 8080, and the image declares a `HEALTHCHECK` against `/health`.

Building the image locally therefore requires running `dx bundle --web --release` first.

### Environment Variables

Copy `.env.example` to `.env`. Key variables: `DATABASE_URL`, `BASE_URL`, `SESSION_SECRET` (hex, 64+ bytes), `FERRISKEY_URL` + `FERRISKEY_REALM` + `FERRISKEY_CLIENT_ID` + `FERRISKEY_CLIENT_SECRET`, SMTP settings, optional Polar billing keys, optional `SENTRY_DSN` + `ENVIRONMENT` (requires `--features sentry`).

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
