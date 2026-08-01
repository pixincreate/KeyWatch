# syntax=docker/dockerfile:1
# Stage 1: Build
# Alpine's musl toolchain produces a fully static binary with no libc
# dependency, so the runtime stage can stay tiny.
FROM rust:1.97.1-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /src

# Copy dependency manifests first for layer caching
COPY Cargo.toml Cargo.lock* ./
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
