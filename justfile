# KeyWatch justfile

default:
    @just --list

# Run the application
run *args="":
    cargo run {{args}}

# Build release binary
build:
    cargo build --release

# Run all tests
test:
    cargo test

# Run tests with output
test-v:
    cargo test -- --nocapture

# Run specific test
test-named name:
    cargo test {{name}}

# Format code
fmt:
    cargo +nightly fmt --all

# Lint with clippy
clippy:
    cargo clippy --all-targets --all-features

# Run clippy with warnings as errors
clippy-strict:
    cargo clippy --all-targets --all-features -- -D warnings

# Build and run release
run-release:
    cargo run --release

# Full check pipeline
check: fmt clippy test
    @echo "✓ All checks passed"

# Run benchmarks (requires criterion)
bench:
    cargo bench

# Generate docs
doc:
    cargo doc --no-deps --open

# Build docs without opening
doc-build:
    cargo doc --no-deps

# Add a new dependency
add dep:
    cargo add {{dep}}

# Remove a dependency
remove dep:
    cargo remove {{dep}}

# Update dependencies
update:
    cargo update

# Audit dependencies for vulnerabilities
audit:
    cargo audit

# Clean build artifacts
clean:
    cargo clean

# Wipe and rebuild from scratch
scrub: clean build

# Check available targets
targets:
    cargo metadata --format-version 1 | jq '.targets[] | select(.kind[0] == "bin") | .name' -r