#!/bin/bash
# KeyWatch pre-push hook
# Installed by KeyWatch

{{repo_section}}KEYWATCH_BIN={{binary_name}}

trim_repository() {
    local repository="$1"
    repository="${repository#"${repository%%[![:space:]]*}"}"
    repository="${repository%"${repository##*[![:space:]]}"}"
    printf '%s' "$repository"
}

normalize_repository_url() {
    local repository lowercase_repository scheme repository_after_scheme authority path host port
    repository=$(trim_repository "$1")
    lowercase_repository=$(printf '%s' "$repository" | tr '[:upper:]' '[:lower:]')

    if [[ "$lowercase_repository" == https://* ]]; then
        scheme="https"
        repository_after_scheme="${repository:8}"
    elif [[ "$lowercase_repository" == http://* ]]; then
        scheme="http"
        repository_after_scheme="${repository:7}"
    elif [[ "$lowercase_repository" == ssh://* ]]; then
        scheme="ssh"
        repository_after_scheme="${repository:6}"
    elif [[ "$repository" == *:* && "${repository%%:*}" != */* ]]; then
        scheme="scp"
        authority="${repository%%:*}"
        path="${repository#*:}"
    else
        scheme="plain"
        repository_after_scheme="$repository"
    fi
    if [ "$scheme" != "scp" ]; then
        [ "$repository_after_scheme" != "${repository_after_scheme#*/}" ] || return 1
        authority="${repository_after_scheme%%/*}"
        path="${repository_after_scheme#*/}"
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
    lowercase_repository=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
    if [[ "$lowercase_repository" == *.git ]]; then path="${path:0:${#path}-4}"; fi
    while [[ "$path" == */ ]]; do path="${path%/}"; done
    [ -n "$host" ] && [[ "$path" == */* ]] || return 1
    [ -n "${path%%/*}" ] && [ -n "${path#*/}" ] || return 1
    [[ "${path#*/}" != */* ]] || return 1
    if [ "$host" = "github.com" ]; then
        path=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
    fi
    printf '%s/%s' "$host" "$path"
}

resolve_remote_url() {
    local remote_name="$1"
    local remote_url="$2"

    if [ -n "$remote_url" ]; then
        printf '%s' "$remote_url"
        return 0
    fi
    git remote get-url --push "$remote_name" 2>/dev/null || git remote get-url "$remote_name" 2>/dev/null || true
}

repository_list_contains() {
    local repositories="$1"
    local current_repository="$2"
    local configured_repository normalized_repository
    local repository_list

    IFS=',' read -r -a repository_list <<< "$repositories"
    for configured_repository in "${repository_list[@]}"; do
        normalized_repository=$(normalize_repository_url "$configured_repository")
        if [ -n "$normalized_repository" ] && [ "$current_repository" = "$normalized_repository" ]; then
            return 0
        fi
    done
    return 1
}

repository_filters_are_configured() {
    [ -n "${ALLOWED_REPOS:-}" ] || [ -n "${BLOCKED_REPOS:-}" ]
}

enforce_repository_policy() {
    local remote_url="$1"
    local current_repository

    current_repository=$(normalize_repository_url "$remote_url" 2>/dev/null || true)
    if [ -z "$remote_url" ]; then
        return 0
    fi

    if [ -z "$current_repository" ] && repository_filters_are_configured; then
        echo "Error: unable to validate remote $remote_url" >&2
        return 1
    fi

    if [ -n "${ALLOWED_REPOS:-}" ] && ! repository_list_contains "$ALLOWED_REPOS" "$current_repository"; then
        echo "Error: push blocked for remote $remote_url" >&2
        return 1
    fi

    if [ -n "${BLOCKED_REPOS:-}" ] && repository_list_contains "$BLOCKED_REPOS" "$current_repository"; then
        echo "Error: push blocked for remote $remote_url" >&2
        return 1
    fi
    return 0
}

main() {
    local remote_name="${1:-origin}"
    local remote_url_arg="${2:-}"
    local remote_url

    if ! command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
        echo "Error: $KEYWATCH_BIN not found on PATH" >&2
        exit 1
    fi
    remote_url=$(resolve_remote_url "$remote_name" "$remote_url_arg")
    enforce_repository_policy "$remote_url" || exit 1
    "$KEYWATCH_BIN" scan . --exit-mode critical
    exit $?
}

main "$@"
