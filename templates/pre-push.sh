#!/bin/bash
# KeyWatch pre-push hook
# Installed by KeyWatch

{{repo_section}}KEYWATCH_BIN={{binary_name}}

if ! command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
    echo "Error: $KEYWATCH_BIN not found on PATH" >&2
    exit 1
fi

CURRENT_REMOTE=$(git remote get-url --push origin 2>/dev/null || git remote get-url origin 2>/dev/null || true)

if [ -n "$CURRENT_REMOTE" ] && [ -n "${ALLOWED_REPOS:-}" ]; then
    allowed_match=0
    IFS=',' read -r -a allowed_list <<< "$ALLOWED_REPOS"
    for allowed_repo in "${allowed_list[@]}"; do
        if [ -n "$allowed_repo" ] && [[ "$CURRENT_REMOTE" == *"$allowed_repo"* ]]; then
            allowed_match=1
            break
        fi
    done

    if [ "$allowed_match" -eq 0 ]; then
        echo "Error: push blocked for remote $CURRENT_REMOTE" >&2
        exit 1
    fi
fi

if [ -n "$CURRENT_REMOTE" ] && [ -n "${BLOCKED_REPOS:-}" ]; then
    IFS=',' read -r -a blocked_list <<< "$BLOCKED_REPOS"
    for blocked_repo in "${blocked_list[@]}"; do
        if [ -n "$blocked_repo" ] && [[ "$CURRENT_REMOTE" == *"$blocked_repo"* ]]; then
            echo "Error: push blocked for remote $CURRENT_REMOTE" >&2
            exit 1
        fi
    done
fi

"$KEYWATCH_BIN" scan . --exit-mode critical
exit $?
