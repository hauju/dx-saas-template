clean:
    cargo clean

fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

check: fmt clippy

init:
    docker compose up -d

serve:
    dx serve --addr 0.0.0.0

tw:
    bunx @tailwindcss/cli -i tailwind.css -o ./assets/tailwind.css
