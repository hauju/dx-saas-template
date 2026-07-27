# Packages the pre-built dx web bundle into a slim runtime image. The build
# itself happens OUTSIDE Docker in CI (see .github/workflows/deploy.yml) so
# cargo/wasm caching works and the runtime image stays tiny. The host/Coolify
# server never compiles anything.
#
# Build the bundle first (CI does this):  dx bundle --web --release
# Migrations (sqlx::migrate!) and docs are embedded into the server binary at
# compile time, so the runtime image ships neither.
FROM debian:trixie-slim

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# The Dioxus server binary reads these; bind 0.0.0.0 to be reachable in a container.
ENV PORT=8080
ENV IP=0.0.0.0

# Pre-built dx bundle output from GitHub Actions (`dx bundle --web --release`).
COPY target/dx/dx-saas-template/release/web /usr/local/app

WORKDIR /usr/local/app

EXPOSE 8080

# /health round-trips a query to PostgreSQL, so this reports unhealthy when the
# process is up but the database is unreachable. start-period covers boot +
# migrations on a cold database.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/app/server"]
