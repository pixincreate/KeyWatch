#!/bin/bash
# KeyWatch pre-commit hook
# Installed by KeyWatch

KEYWATCH_BIN={{binary_name}}
EXCLUDE_PATTERNS={{exclude_patterns}}

if ! command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
    echo "Error: $KEYWATCH_BIN not found on PATH" >&2
    exit 1
fi

while IFS= read -r -d '' file; do
    if [ -z "$file" ]; then
        continue
    fi
    if [ ! -f "$file" ]; then
        continue
    fi
    if "$KEYWATCH_BIN" --file "$file" --exclude "$EXCLUDE_PATTERNS" 2>/dev/null; then
        continue
    fi
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 1 ]; then
        echo "ERROR: Secret detected in $file"
        "$KEYWATCH_BIN" --file "$file" --exclude "$EXCLUDE_PATTERNS" --verbose
        exit 1
    fi
    echo "Error: key-watch failed on $file (exit code: $EXIT_CODE)" >&2
    exit 1
done < <(git diff --cached --name-only -z)

exit 0
