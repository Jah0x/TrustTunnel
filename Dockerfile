# syntax=docker/dockerfile:1

FROM rust:1.85-bookworm AS builder
WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY endpoint ./endpoint
COPY lib ./lib
COPY macros ./macros

RUN cargo build --package trusttunnel_endpoint --release

FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=builder /workspace/target/release/trusttunnel_endpoint /usr/local/bin/trusttunnel-endpoint

EXPOSE 8443/tcp

ENTRYPOINT ["/usr/local/bin/trusttunnel-endpoint"]
CMD ["/etc/trusttunnel/vpn.toml", "/etc/trusttunnel/hosts.toml", "-l", "info"]
