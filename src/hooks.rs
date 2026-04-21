use crate::cli::CliOptions;

pub fn generate_pre_push_hook(options: &CliOptions) -> String {
    let binary = hook_binary_name();

    let escape_shell = |s: &str| -> String {
        s.replace('\'', "'\"'\"'")
            .chars()
            .filter(|c| c.is_alphanumeric() || "-_./@".contains(*c))
            .collect()
    };

    let allowed_repos = options
        .allowed_repos
        .as_deref()
        .map(escape_shell)
        .unwrap_or_default();
    let blocked_repos = options
        .blocked_repos
        .as_deref()
        .map(escape_shell)
        .unwrap_or_default();

    let repo_section = if allowed_repos.is_empty() && blocked_repos.is_empty() {
        String::new()
    } else {
        format!(
            "ALLOWED_REPOS='{}'\nBLOCKED_REPOS='{}'\n",
            allowed_repos, blocked_repos
        )
    };

    format!(
        r#"#!/bin/bash
# KeyWatch pre-push hook
# Installed by KeyWatch

{repo_section}KEYWATCH_BIN='{binary}'

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
"#
    )
}

pub fn generate_pre_commit_hook(options: &CliOptions) -> String {
    let binary = hook_binary_name();
    let exclude_patterns = options
        .exclude
        .as_deref()
        .map(|s| s.replace('\'', "'\"'\"'"))
        .unwrap_or_default();

    format!(
        r#"#!/bin/bash
# KeyWatch pre-commit hook
# Installed by KeyWatch

KEYWATCH_BIN='{binary}'
EXCLUDE_PATTERNS='{exclude_patterns}'

if ! command -v "$KEYWATCH_BIN" >/dev/null 2>&1; then
    echo "Error: key-watch not found on PATH" >&2
    exit 1
fi

if [ ! -f "detectors.toml" ]; then
    echo "Error: detectors.toml not found in current directory" >&2
    exit 1
fi

git diff --cached --name-only | while IFS= read -r file; do
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
done

exit 0
"#
    )
}

fn hook_binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "key-watch".to_string())
}
