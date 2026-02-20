# syntax=docker/dockerfile:1

FROM rust:1.85-bookworm AS builder
WORKDIR /workspace

COPY . .

RUN set -eux; \
    cargo build --manifest-path endpoint/Cargo.toml --release --bin trusttunnel_endpoint; \
    install -D target/release/trusttunnel_endpoint /usr/local/bin/trusttunnel-endpoint

FROM gcr.io/distroless/cc-debian11 AS runtime

COPY --from=builder /usr/local/bin/trusttunnel-endpoint /usr/local/bin/trusttunnel-endpoint

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/trusttunnel-endpoint", "/etc/trusttunnel/vpn.toml", "/etc/trusttunnel/hosts.toml", "-l", "info"]
