#!/usr/bin/env bash

# KeyWatch Uninstallation Script
# Removes key-watch binary from ~/.local/bin or /usr/local/bin

set -e

BINARY_NAME="key-watch"
USER_INSTALL_DIR="${HOME}/.local/bin"
SYSTEM_INSTALL_DIR="/usr/local/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

main() {
    local system_wide=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --system)
                system_wide=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --system    Remove from system-wide /usr/local/bin"
                echo "  --help,-h   Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    if [ "$system_wide" = true ]; then
        if [ "$(id -u)" -ne 0 ]; then
            log_error "System-wide removal requires sudo"
            exit 1
        fi
        install_dir="${SYSTEM_INSTALL_DIR}"
    else
        install_dir="${USER_INSTALL_DIR}"
    fi

    if [ ! -f "${install_dir}/${BINARY_NAME}" ]; then
        log_warn "${BINARY_NAME} not found at ${install_dir}"
        exit 0
    fi

    log_info "Removing ${BINARY_NAME} from ${install_dir}..."
    rm -f "${install_dir}/${BINARY_NAME}"

    if [ "$system_wide" = false ] && [ -d "${USER_INSTALL_DIR}" ] && [ -z "$(ls -A ${USER_INSTALL_DIR} 2>/dev/null)" ]; then
        log_info "Cleaning up empty ${USER_INSTALL_DIR}..."
        rmdir "${USER_INSTALL_DIR}"
    fi

    log_info "Uninstallation complete!"
}

main "$@"