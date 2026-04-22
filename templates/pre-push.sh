#!/bin/bash
# KeyWatch pre-push hook
# Installed by KeyWatch

{{repo_section}}KEYWATCH_BIN='{{binary_name}}'

find_keywatch() {
    if command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
        return 0
    fi
    local hook_dir="$(cd "$(dirname "$0")" && pwd)"
    if [ -x "$hook_dir/$KEYWATCH_BIN" ]; then
        KEYWATCH_BIN="$hook_dir/$KEYWATCH_BIN"
        return 0
    fi
    if [ -x "$hook_dir/../target/debug/$KEYWATCH_BIN" ]; then
        KEYWATCH_BIN="$hook_dir/../target/debug/$KEYWATCH_BIN"
        return 0
    fi
    return 1
}

if ! find_keywatch; then
    echo "Error: key-watch not found" >&2
    exit 1
fi

if [ ! -f "detectors.toml" ]; then
    echo "Error: detectors.toml not found in current directory" >&2
    exit 1
fi

"$KEYWATCH_BIN" --dir . --exit-mode critical
exit $?