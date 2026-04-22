#!/usr/bin/env bash

# KeyWatch Installation Script
# Installs key-watch binary to ~/.local/bin (or /usr/local/bin with sudo)
# Adds to PATH if needed

set -e

INSTALL_DIR="${HOME}/.local/bin"
BINARY_NAME="key-watch"
SYSTEM_INSTALL_DIR="/usr/local/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Find the binary
find_binary() {
    local binary_path=""

    # Check release build first
    if [ -f "target/release/${BINARY_NAME}" ]; then
        binary_path="target/release/${BINARY_NAME}"
    # Then debug build
    elif [ -f "target/debug/${BINARY_NAME}" ]; then
        binary_path="target/debug/${BINARY_NAME}"
    # Check if already installed
    elif command -v "${BINARY_NAME}" &> /dev/null; then
        log_info "${BINARY_NAME} is already installed"
        exit 0
    else
        log_error "Binary not found. Please run 'cargo build --release' first."
        exit 1
    fi

    echo "$binary_path"
}

# Check if directory is in PATH
is_in_path() {
    echo "$PATH" | tr ':' '\n' | grep -qx "$1"
}

# Add to PATH if not present
add_to_path() {
    local shell_rc=""

    # Detect shell
    case "${SHELL}" in
        */zsh*)
            shell_rc="${HOME}/.zshrc"
            ;;
        */bash*)
            shell_rc="${HOME}/.bashrc"
            ;;
        */fish*)
            shell_rc="${HOME}/.config/fish/config.fish"
            ;;
        *)
            shell_rc="${HOME}/.profile"
            ;;
    esac

    if [ -n "$1" ] && ! is_in_path "$1"; then
        log_warn "${1} is not in your PATH"
        log_info "Add the following to your ${shell_rc}:"
        echo ""
        echo "    export PATH=\"\${HOME}/.local/bin:\${PATH}\""
        echo ""
    fi
}

# Main installation
main() {
    local install_system=false
    local force=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --system)
                install_system=true
                shift
                ;;
            --force)
                force=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --system    Install system-wide to /usr/local/bin (requires sudo)"
                echo "  --force     Overwrite existing installation"
                echo "  --help,-h   Show this help message"
                echo ""
                echo "Default: Install to ~/.local/bin"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    local binary_path
    binary_path=$(find_binary)

    # Determine installation directory
    if [ "$install_system" = true ]; then
        if [ "$(id -u)" -ne 0 ]; then
            log_error "System-wide installation requires sudo"
            log_info "Run with --system flag and enter your password when prompted"
            exit 1
        fi
        INSTALL_DIR="${SYSTEM_INSTALL_DIR}"
    fi

    # Check if already installed
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ] && [ "$force" = false ]; then
        log_error "${BINARY_NAME} is already installed at ${INSTALL_DIR}"
        log_info "Use --force to overwrite"
        exit 1
    fi

    # Create install directory if needed
    if [ ! -d "$INSTALL_DIR" ]; then
        log_info "Creating ${INSTALL_DIR}..."
        mkdir -p "$INSTALL_DIR"
    fi

    # Copy binary
    log_info "Installing ${BINARY_NAME} to ${INSTALL_DIR}..."
    cp "$binary_path" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    # Add to PATH if needed
    if [ "$install_system" = false ]; then
        add_to_path "$INSTALL_DIR"
    fi

    log_info "Installation complete!"
    log_info "Run '${BINARY_NAME} --help' to get started"
}

main "$@"