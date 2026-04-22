#!/bin/bash
# KeyWatch pre-push hook
# Installed by KeyWatch

{{repo_section}}KEYWATCH_BIN='{{binary_name}}'

if ! command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
    echo "Error: key-watch not found on PATH" >&2
    exit 1
fi

if [ ! -f "detectors.toml" ]; then
    echo "Error: detectors.toml not found in current directory" >&2
    exit 1
fi

"$KEYWATCH_BIN" --dir . --exit-mode critical
exit $?