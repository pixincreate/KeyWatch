# syntax=docker/dockerfile:1
# Stage 1: Build
FROM rust:1.85-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /src

# Copy dependency manifests first for layer caching
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
COPY detectors.toml .

RUN cargo build --locked --release && \
    strip target/release/key-watch && \
    cp target/release/key-watch /key-watch

# Stage 2: Runtime
FROM alpine:3.21

RUN apk add --no-cache ca-certificates && \
    adduser -D keywatch

COPY --from=build /key-watch /usr/local/bin/key-watch
COPY --from=build /src/detectors.toml /etc/keywatch/detectors.toml

USER keywatch

ENV KEYWATCH_CONFIG_PATH=/etc/keywatch/detectors.toml

ENTRYPOINT ["key-watch"]
CMD ["--help"]
