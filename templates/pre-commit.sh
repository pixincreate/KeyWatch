#!/bin/bash
# KeyWatch pre-commit hook
# Installed by KeyWatch

KEYWATCH_BIN={{binary_name}}
EXCLUDE_PATTERNS={{exclude_patterns}}

if ! command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
    echo "Error: $KEYWATCH_BIN not found on PATH" >&2
    exit 1
fi

# scan --staged reads only the added lines of git diff --cached, so findings
# on unchanged lines never block a commit. A git failure inside the scanner
# exits with code 2, which fails the hook closed.
#
# --no-config-discovery makes the hook use KeyWatch's built-in detectors, as
# the pre-push hook already does. Without it a detectors.toml committed to the
# scanned repository REPLACES the detector set, so a repository could disable
# secret detection for everyone who clones it. Suppress findings with a
# committed baseline or an inline keywatch:ignore marker, both of which the
# hook still honours.
"$KEYWATCH_BIN" scan --staged --no-config-discovery --exclude "$EXCLUDE_PATTERNS" >/dev/null 2>&1
EXIT_CODE=$?
case $EXIT_CODE in
    0)
        exit 0
        ;;
    1)
        echo "ERROR: Secret detected in staged changes. Run '$KEYWATCH_BIN scan --staged' to inspect."
        exit 1
        ;;
    *)
        echo "Error: $KEYWATCH_BIN scan --staged failed (exit code: $EXIT_CODE)" >&2
        exit 1
        ;;
esac
