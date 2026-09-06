# dx-saas-template

A production-ready fullstack **Dioxus 0.7** SaaS template in Rust. One codebase compiles into a
WASM client and an Axum server; auth, sessions, billing, email, and docs are pre-wired.

- 🦀 Rust + Axum + Dioxus
- 💾 PostgreSQL
- 🔐 Email OTP + passkeys, FerrisKey OIDC optional (auth)
- 📧 Scaleway (email)
- 💳 Polar (billing)
- 🐳 Coolify (server)

Self-hosted. EU-hosted. GDPR-first.

## Used in production by

- [seggwat.com](https://seggwat.com)
- [infra.page](https://infra.page)
- [stepshots.com](https://stepshots.com)

## Stack

| Layer           | Choice                                                                  |
| --------------- | ----------------------------------------------------------------------- |
| UI framework    | [Dioxus 0.7](https://dioxuslabs.com) (fullstack, SSR + WASM hydration)  |
| Styling         | TailwindCSS 4 + DaisyUI 5 (dark theme), Lucide icons                    |
| Server          | Axum 0.8, tower-sessions (Postgres-backed)                              |
| Database        | PostgreSQL 18 (sqlx, compile-time-checked queries, embedded migrations) |
| Auth            | Email OTP + passkeys in your own DB by default; FerrisKey OIDC behind `AUTH_MODE=ferriskey` — [`dx-auth`](https://github.com/hauju/dx-kit) |
| Billing         | [Polar.sh](https://polar.sh) — customers, subscriptions, webhooks       |
| Email           | SMTP via `lettre` (async pool) — [`dx-smtp`](https://github.com/hauju/dx-kit); [Mailpit](https://mailpit.axllent.org) for local dev |
| Docs site       | [dioxus-docs-kit](https://crates.io/crates/dioxus-docs-kit) v0.4 at `/docs` |
| Error tracking  | Sentry (optional, feature-gated)                                        |

## Layout

```
.
├── Cargo.toml            # Workspace root
├── src/                  # App binary (dual entry: server + WASM client)
│   ├── main.rs           # Axum server + Dioxus launch
│   ├── routes.rs         # Route enum + layouts
│   ├── pages/            # Home, Login, Dashboard, Settings, Docs
│   ├── components/       # Navbar, DashboardShell, ToastProvider
│   ├── models/           # Shared types (UserEntity, AppError)
│   └── server/           # Server-only: AppState, Config, DB, auth-store impl
├── crates/
│   └── polar/            # Polar.sh billing API + webhook verification
│                         # (auth, crypto, smtp come from dx-kit, pinned by git tag)
├── docs/                 # MDX docs, embedded at compile time via dioxus-docs-kit
├── migrations/           # SQL migrations, applied on boot via sqlx::migrate!
├── .sqlx/                # Query metadata so sqlx macros build without a database
├── docker-compose.yml    # PostgreSQL + Mailpit
└── Dockerfile            # Two-stage production build
```

## Quickstart

### Prerequisites

- Rust 1.94 (pinned via `rust-toolchain.toml`)
- [Dioxus CLI](https://dioxuslabs.com): `curl -sSL https://dioxus.dev/install.sh | sh`
- [Bun](https://bun.sh) for Tailwind
- Docker (for Postgres, Mailpit)
- [`just`](https://github.com/casey/just) (optional, for shortcuts)

### Run it

```sh
# 1. Start infra (Postgres, Mailpit)
docker compose up -d
# or: just init

# 2. Bootstrap .env with a fresh SESSION_SECRET
just bootstrap

# 3. Install node deps (for Tailwind)
bun install

# 4. Run the dev server (auto-reloads on save)
dx serve --addr 0.0.0.0
# or: just serve
```

App runs on <http://localhost:8080>. Docs at `/docs`, Mailpit UI at <http://localhost:8025>.

## Feature flags

The binary compiles in two modes from the same crate:

- `--features web` (default) → WASM client
- `--features server` → Axum server with PostgreSQL, auth, billing, email
- `--features sentry` → enables Sentry error tracking (requires `SENTRY_DSN`)

`dx serve` and `dx build` handle these transparently.

## Changing the database schema

Queries are checked against the schema at compile time, with the metadata committed
in `.sqlx/` so a fresh clone builds with nothing running. After editing any SQL or
adding a migration, regenerate it:

```sh
docker compose up -d
cargo sqlx prepare -- --no-default-features --features server
```

Editing a query without re-preparing fails the next build, since no cached entry
matches it. Editing the *schema* without re-preparing does not: entries are keyed
by the query text, so untouched queries keep matching stale metadata and compile
fine. CI's `schema` job catches that by building against a real database.

Install the CLI with
`cargo install sqlx-cli --no-default-features --features rustls,postgres`.

## CI gates

Local parity with GitHub Actions:

```sh
bun install --frozen-lockfile
bunx @tailwindcss/cli -i tailwind.css -o assets/tailwind.css  # required for clippy
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo machete
cargo test --workspace --exclude dx-saas-template
```

## Using this template

Clone the repo, then rename the project:

```sh
# Updates package name, DB name, tracing filter, and Dockerfile binary path.
just rename my-new-project
```

Then update `repository` in `Cargo.toml`, replace the placeholder `/legal` pages, wire Polar credentials in `.env`,
and replace `LICENSE` with your own if needed.

## License

MIT — see [LICENSE](LICENSE).
