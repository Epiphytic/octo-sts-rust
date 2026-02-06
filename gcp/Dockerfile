# Build stage
FROM rust:1.83-slim AS builder

WORKDIR /app

# Copy workspace files
COPY Cargo.toml ./
COPY core/ core/
COPY gcp/ gcp/
# Need cloudflare/ listed in workspace members but don't need to compile it
COPY cloudflare/Cargo.toml cloudflare/Cargo.toml
RUN mkdir -p cloudflare/src && echo "// stub" > cloudflare/src/lib.rs

# Build only the GCP binary
RUN cargo build -p octo-sts-gcp --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/octo-sts-gcp /usr/local/bin/octo-sts-gcp

ENV PORT=8080
EXPOSE 8080

CMD ["octo-sts-gcp"]
