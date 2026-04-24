#!/bin/sh
# KeyWatch install/uninstall script

BINARY_NAME="key-watch"
INSTALL_DIR="${HOME}/.local/bin"

case "$1" in
    uninstall|remove)
        if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
            rm -f "${INSTALL_DIR}/${BINARY_NAME}"
            echo "Removed ${BINARY_NAME} from ${INSTALL_DIR}"
        fi
        for alt in keywatch watch; do
            if [ -L "${INSTALL_DIR}/${alt}" ]; then
                rm -f "${INSTALL_DIR}/${alt}"
                echo "Removed ${alt} alias"
            fi
        done
        ;;
    install|"")
        if command -v cargo >/dev/null 2>&1; then
            echo "Installing via cargo..."
            cargo install --git https://github.com/pixincreate/KeyWatch.git || cargo install --path .
            exit $?
        fi

        echo "cargo not found. Looking for pre-built binary..."

        BIN_PATH=""
        for path in "./target/release/${BINARY_NAME}" "./target/debug/${BINARY_NAME}"; do
            if [ -f "$path" ]; then
                BIN_PATH="$path"
                break
            fi
        done

        if [ -z "$BIN_PATH" ] && [ -n "$2" ] && [ -f "$2" ]; then
            BIN_PATH="$2"
        fi

        if [ -z "$BIN_PATH" ]; then
            echo "Binary not found. Build with 'cargo build --release' or provide path:"
            echo "  $0 install /path/to/key-watch"
            exit 1
        fi

        mkdir -p "${INSTALL_DIR}"
        cp "$BIN_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

        ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/keywatch" 2>/dev/null || true
        ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/watch" 2>/dev/null || true

        echo "Installed to ${INSTALL_DIR}"
        echo "Add ${INSTALL_DIR} to your PATH if not already present"
        ;;
    *)
        echo "Usage: $0 [install|uninstall] [/path/to/binary]"
        ;;
esac