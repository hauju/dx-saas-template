# Packages the pre-built dx web bundle into a slim runtime image. The build
# itself happens OUTSIDE Docker in CI (see .github/workflows/deploy.yml) so
# cargo/wasm caching works and the runtime image stays tiny. The host/Coolify
# server never compiles anything.
#
# Build the bundle first (CI does this):  dx bundle --web --release
# Docs are embedded into the server binary at compile time.
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

ENTRYPOINT ["/usr/local/app/server"]
