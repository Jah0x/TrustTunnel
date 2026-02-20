# syntax=docker/dockerfile:1

FROM rust:1.85.1-bookworm AS builder
WORKDIR /workspace

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libclang-dev \
        make \
        perl \
        pkg-config; \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN set -eux; \
    cargo build --manifest-path endpoint/Cargo.toml --release --bin trusttunnel_endpoint; \
    install -D target/release/trusttunnel_endpoint /usr/local/bin/trusttunnel-endpoint

FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=builder /usr/local/bin/trusttunnel-endpoint /usr/local/bin/trusttunnel-endpoint

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/trusttunnel-endpoint", "/etc/trusttunnel/vpn.toml", "/etc/trusttunnel/hosts.toml", "-l", "info"]
