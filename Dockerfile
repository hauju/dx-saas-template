FROM rust:1.86 AS builder

# Install dioxus CLI
RUN curl -sSL https://dioxus.dev/install.sh | sh -s -- 0.7.9

# Install bun for Tailwind CSS
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

WORKDIR /app

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Create a dummy main.rs so dependencies can be compiled
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --features server
RUN rm -rf src

# Copy the real source and assets
COPY src/ src/
COPY assets/ assets/
COPY docs/ docs/
COPY build.rs tailwind.css Dioxus.toml ./
COPY package.json bun.lock ./

# Build Tailwind CSS (needed before dx build)
RUN bun install --frozen-lockfile
RUN bunx @tailwindcss/cli -i tailwind.css -o assets/tailwind.css

# Build the full application
RUN dx build --release --platform web

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/dist/ ./dist/

EXPOSE 8080

CMD ["./dist/dx-saas-template"]
