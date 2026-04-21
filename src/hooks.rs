use crate::cli::CliOptions;

const PRE_PUSH_TEMPLATE: &str = include_str!("../templates/pre-push.sh");
const PRE_COMMIT_TEMPLATE: &str = include_str!("../templates/pre-commit.sh");

const SAFE_CHARS: &str = "-_./@";
const DEFAULT_BINARY_NAME: &str = "key-watch";

fn shell_escape(input: &str) -> String {
    input
        .replace('\'', "'\"'\"'")
        .chars()
        .filter(|character| character.is_alphanumeric() || SAFE_CHARS.contains(*character))
        .collect()
}

fn build_repo_section(allowed: Option<&str>, blocked: Option<&str>) -> String {
    let escaped_allowed = allowed.map(shell_escape);
    let escaped_blocked = blocked.map(shell_escape);

    if escaped_allowed.is_none() && escaped_blocked.is_none() {
        return String::new();
    }

    let allowed_line = escaped_allowed.map_or(String::new(), |escaped| {
        format!("ALLOWED_REPOS='{}'\n", escaped)
    });
    let blocked_line = escaped_blocked.map_or(String::new(), |escaped| {
        format!("BLOCKED_REPOS='{}'\n", escaped)
    });
    format!("{}{}", allowed_line, blocked_line)
}

fn render_pre_push(options: &CliOptions) -> String {
    let binary_name = hook_binary_name();
    let repo_section = build_repo_section(
        options.allowed_repos.as_deref(),
        options.blocked_repos.as_deref(),
    );

    PRE_PUSH_TEMPLATE
        .replace("{{binary_name}}", &binary_name)
        .replace("{{repo_section}}", &repo_section)
}

fn render_pre_commit(options: &CliOptions) -> String {
    let binary_name = hook_binary_name();
    let exclude_patterns = options
        .exclude
        .as_deref()
        .map(shell_escape)
        .unwrap_or_default();

    PRE_COMMIT_TEMPLATE
        .replace("{{binary_name}}", &binary_name)
        .replace("{{exclude_patterns}}", &exclude_patterns)
}

pub fn generate_pre_push_hook(options: &CliOptions) -> String {
    render_pre_push(options)
}

pub fn generate_pre_commit_hook(options: &CliOptions) -> String {
    render_pre_commit(options)
}

fn hook_binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| DEFAULT_BINARY_NAME.to_string())
}
