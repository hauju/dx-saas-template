clean:
    cargo clean

fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Mirrors the CI test jobs: the app crate needs the server feature selected
# explicitly, since its default feature builds the wasm client.
test:
    cargo test --workspace --exclude dx-saas-template
    cargo test -p dx-saas-template --no-default-features --features server

check: fmt clippy test

# Regenerate the committed sqlx query metadata after changing SQL or migrations.
# Needs a running database (`just init`).
prepare:
    cargo sqlx prepare -- --no-default-features --features server

init:
    docker compose up -d

# Optional FerrisKey for AUTH_MODE=ferriskey: starts it and creates the realm and
# client the app expects (see scripts/ferriskey-bootstrap.sh).
ferriskey:
    docker compose --profile ferriskey up -d
    scripts/ferriskey-bootstrap.sh

# Regenerate the Tailwind safelist for dx-auth's login pages after moving the pin.
safelist:
    python3 scripts/dx-auth-safelist.py

serve:
    dx serve --addr 0.0.0.0

tw:
    bunx @tailwindcss/cli -i tailwind.css -o ./assets/tailwind.css

# Copy .env.example -> .env and fill in a freshly generated SESSION_SECRET.
bootstrap:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -f .env ]]; then
        echo ".env already exists; refusing to overwrite."
        exit 1
    fi
    cp .env.example .env
    SECRET=$(openssl rand -hex 64)
    perl -i -pe "s/^SESSION_SECRET=\$/SESSION_SECRET=$SECRET/" .env
    echo "Wrote .env with a fresh SESSION_SECRET."

# Rename the template project. Pass a kebab-case name, e.g. `just rename my-app`.
# Updates package name, Postgres db/user name, tracing filter, Dockerfile binary path, and docs.
rename new-name:
    #!/usr/bin/env bash
    set -euo pipefail
    KEBAB="{{new-name}}"
    SNAKE="${KEBAB//-/_}"
    if [[ "$KEBAB" == "dx-saas-template" ]]; then
        echo "Name unchanged; aborting."
        exit 1
    fi
    if ! [[ "$KEBAB" =~ ^[a-z][a-z0-9-]*$ ]]; then
        echo "Invalid name: use lowercase letters, digits, and hyphens only."
        exit 1
    fi
    git ls-files \
        | grep -vE '^(Cargo\.lock|bun\.lock|LICENSE|justfile|assets/.*)$' \
        | while read -r f; do
            perl -i -pe "s/dx_saas_template/$SNAKE/g; s/dx-saas-template/$KEBAB/g; s/\\bdx_saas\\b/$SNAKE/g" "$f"
        done
    echo "Renamed dx-saas-template -> $KEBAB (snake: $SNAKE)."
    echo "Run 'cargo build' to regenerate Cargo.lock."
