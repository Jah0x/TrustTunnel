# syntax=docker/dockerfile:1

FROM rust:1.85-bookworm AS builder
WORKDIR /workspace

COPY . .

RUN set -eux; \
    BIN_NAME="$(awk '\n        /^\[\[bin\]\]$/ { in_bin = 1; next }\n        /^\[/ && $0 != "[[bin]]" { in_bin = 0 }\n        in_bin && /^name\s*=\s*"/ { gsub(/.*"|".*/, "", $0); print; exit }\n    ' endpoint/Cargo.toml)"; \
    if [ -z "$BIN_NAME" ]; then \
        BIN_NAME="$(awk -F '"' '/^name\s*=\s*"/ { print $2; exit }' endpoint/Cargo.toml)"; \
    fi; \
    cargo build --manifest-path endpoint/Cargo.toml --release --bin "$BIN_NAME"; \
    install -D "target/release/$BIN_NAME" /usr/local/bin/trusttunnel-endpoint

FROM gcr.io/distroless/cc-debian11 AS runtime

COPY --from=builder /usr/local/bin/trusttunnel-endpoint /usr/local/bin/trusttunnel-endpoint

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/trusttunnel-endpoint", "/etc/trusttunnel/vpn.toml", "/etc/trusttunnel/hosts.toml", "-l", "info"]
