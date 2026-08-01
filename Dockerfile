# syntax=docker/dockerfile:1
# Stage 1: Build
# Alpine's musl toolchain produces a fully static binary with no libc
# dependency, so the runtime stage can stay tiny.
#
# Pin to the MSRV declared in Cargo.toml (rust-version = "1.85") so the
# Docker build always uses the minimum supported compiler, not whatever
# happens to be "latest" at build time.
FROM rust:1.85-alpine3.21 AS build

RUN apk add --no-cache musl-dev

WORKDIR /src

# Copy manifests and sources together; Cargo.lock is required for --locked.
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY templates/ templates/
COPY detectors.toml .

RUN cargo build --locked --release && \
    strip target/release/key-watch

# Stage 2: Runtime
# Alpine provides git (required for --git-history scanning and hook
# installation). The binary is statically linked against musl, so no libc
# needs to be installed.
FROM alpine:3.23

RUN apk add --no-cache git ca-certificates && \
    adduser -D keywatch

COPY --from=build /src/target/release/key-watch /usr/local/bin/key-watch
COPY --from=build /src/detectors.toml /etc/keywatch/detectors.toml

USER keywatch

ENV KEYWATCH_CONFIG_PATH=/etc/keywatch/detectors.toml

ENTRYPOINT ["key-watch"]
CMD ["--help"]
