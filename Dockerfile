# syntax=docker/dockerfile:1
# Stage 1: Build
# Alpine's musl toolchain produces a fully static binary with no libc
# dependency, so the runtime stage can be `scratch` (a few KB).
FROM rust:1.85-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /src

# Copy dependency manifests first for layer caching
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
COPY detectors.toml .

RUN cargo build --locked --release && \
    strip target/release/key-watch

# Stage 2: Runtime
# scratch = empty image, only what we COPY in. No shell, no package manager,
# no attack surface beyond the binary itself.
FROM scratch

COPY --from=build /src/target/release/key-watch /usr/local/bin/key-watch
COPY --from=build /src/detectors.toml /etc/keywatch/detectors.toml

# Numeric UID/GID: no /etc/passwd exists in scratch
USER 65532:65532

ENV KEYWATCH_CONFIG_PATH=/etc/keywatch/detectors.toml

# Absolute path required: scratch has no PATH resolution
ENTRYPOINT ["/usr/local/bin/key-watch"]
CMD ["--help"]
