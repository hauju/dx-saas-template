# dx-saas-template

A production-ready fullstack **Dioxus 0.7** SaaS template in Rust. One codebase compiles into a
WASM client and an Axum server; auth, sessions, billing, email, and docs are pre-wired.

- 🦀 Rust + Axum + Dioxus
- 💾 MongoDB
- 🔐 Zitadel (auth)
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
| Server          | Axum 0.8, tower-sessions (Redis-backed)                                 |
| Database        | MongoDB 3.x (replica set for transactions)                              |
| Sessions cache  | Redis / Valkey                                                          |
| Auth            | Zitadel OIDC + Session API v2 (passkey-ready)                           |
| Billing         | [Polar.sh](https://polar.sh) — customers, subscriptions, webhooks       |
| Email           | SMTP via `lettre` (async pool); [Mailpit](https://mailpit.axllent.org) for local dev |
| Object storage  | S3-compatible (`crates/storage`) — ready to wire                        |
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
│   ├── auth/             # Zitadel OIDC + Session API v2, CSRF, rate-limiting
│   ├── crypto/           # Argon2 hashing, AES-256-GCM, token generation
│   ├── smtp/             # lettre async/sync pools
│   ├── polar/            # Polar.sh billing API + webhook verification
│   └── storage/          # S3-compatible storage (AWS, MinIO, R2, Spaces)
├── docs/                 # MDX docs, embedded at compile time via dioxus-docs-kit
├── docker-compose.yml    # MongoDB (replica set) + Redis + Mailpit
└── Dockerfile            # Two-stage production build
```

## Quickstart

### Prerequisites

- Rust 1.94 (pinned via `rust-toolchain.toml`)
- [Dioxus CLI](https://dioxuslabs.com): `curl -sSL https://dioxus.dev/install.sh | sh`
- [Bun](https://bun.sh) for Tailwind
- Docker (for Mongo, Redis, Mailpit)
- [`just`](https://github.com/casey/just) (optional, for shortcuts)

### Run it

```sh
# 1. Start infra (Mongo replica set, Redis, Mailpit)
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
- `--features server` → Axum server with MongoDB, Redis, auth, billing, email
- `--features sentry` → enables Sentry error tracking (requires `SENTRY_DSN`)

`dx serve` and `dx build` handle these transparently.

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

Then update `repository` in `Cargo.toml`, wire Zitadel + Polar credentials in `.env`,
and replace `LICENSE` with your own if needed.

## License

MIT — see [LICENSE](LICENSE).
