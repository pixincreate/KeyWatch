#!/bin/bash
# KeyWatch pre-push hook
# Installed by KeyWatch

{{repo_section}}KEYWATCH_BIN={{binary_name}}

if ! command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
    echo "Error: $KEYWATCH_BIN not found on PATH" >&2
    exit 1
fi

REMOTE_NAME=${1:-origin}
CURRENT_REMOTE=${2:-}
if [ -z "$CURRENT_REMOTE" ]; then
    CURRENT_REMOTE=$(git remote get-url --push "$REMOTE_NAME" 2>/dev/null || git remote get-url "$REMOTE_NAME" 2>/dev/null || true)
fi

trim_repo() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

normalize_repo() {
    local repo lower scheme rest authority path host port
    repo=$(trim_repo "$1")
    lower=$(printf '%s' "$repo" | tr '[:upper:]' '[:lower:]')

    if [[ "$lower" == https://* ]]; then
        scheme="https"
        rest="${repo:8}"
    elif [[ "$lower" == http://* ]]; then
        scheme="http"
        rest="${repo:7}"
    elif [[ "$lower" == ssh://* ]]; then
        scheme="ssh"
        rest="${repo:6}"
    elif [[ "$repo" == *:* && "${repo%%:*}" != */* ]]; then
        scheme="scp"
        authority="${repo%%:*}"
        path="${repo#*:}"
    else
        scheme="plain"
        rest="$repo"
    fi

    if [ "$scheme" != "scp" ]; then
        [ "$rest" != "${rest#*/}" ] || return 1
        authority="${rest%%/*}"
        path="${rest#*/}"
    fi

    authority="${authority##*@}"
    host="${authority%%:*}"
    port=""
    if [[ "$authority" == *:* ]]; then
        port="${authority#*:}"
        [[ "$port" != *:* ]] || return 1
    fi
    host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')

    case "$scheme:$port" in
        https:443|http:80|ssh:22) port="" ;;
    esac
    if [ -n "$port" ]; then
        host="$host:$port"
    fi

    while [[ "$path" == */ ]]; do path="${path%/}"; done
    lower=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
    if [[ "$lower" == *.git ]]; then path="${path:0:${#path}-4}"; fi
    while [[ "$path" == */ ]]; do path="${path%/}"; done

    [ -n "$host" ] && [[ "$path" == */* ]] || return 1
    [ -n "${path%%/*}" ] && [ -n "${path#*/}" ] || return 1
    [[ "${path#*/}" != */* ]] || return 1
    if [ "$host" = "github.com" ]; then
        path=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
    fi
    printf '%s/%s' "$host" "$path"
}

CURRENT_REPO=$(normalize_repo "$CURRENT_REMOTE" 2>/dev/null || true)

if [ -n "$CURRENT_REMOTE" ] && [ -z "$CURRENT_REPO" ] && { [ -n "${ALLOWED_REPOS:-}" ] || [ -n "${BLOCKED_REPOS:-}" ]; }; then
    echo "Error: unable to validate remote $CURRENT_REMOTE" >&2
    exit 1
fi

if [ -n "$CURRENT_REMOTE" ] && [ -n "${ALLOWED_REPOS:-}" ]; then
    allowed_match=0
    IFS=',' read -r -a allowed_list <<< "$ALLOWED_REPOS"
    for allowed_repo in "${allowed_list[@]}"; do
        allowed_repo=$(normalize_repo "$allowed_repo")
        if [ -n "$allowed_repo" ] && [ "$CURRENT_REPO" = "$allowed_repo" ]; then
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
        blocked_repo=$(normalize_repo "$blocked_repo")
        if [ -n "$blocked_repo" ] && [ "$CURRENT_REPO" = "$blocked_repo" ]; then
            echo "Error: push blocked for remote $CURRENT_REMOTE" >&2
            exit 1
        fi
    done
fi

"$KEYWATCH_BIN" scan . --exit-mode critical
exit $?
