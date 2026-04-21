use crate::cli::CliOptions;

const PRE_PUSH_TEMPLATE: &str = include_str!("../templates/pre-push.sh");
const PRE_COMMIT_TEMPLATE: &str = include_str!("../templates/pre-commit.sh");

const SAFE_CHARS: &str = "-_./@";

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

fn render_template(
    template: &str,
    binary_name: &str,
    repo_section: &str,
    exclude_patterns: &str,
) -> String {
    template
        .replace("{{binary_name}}", binary_name)
        .replace("{{allowed_repos_section}}", "")
        .replace("{{blocked_repos_section}}", repo_section)
        .replace("{{exclude_patterns}}", exclude_patterns)
}

pub fn generate_pre_push_hook(options: &CliOptions) -> String {
    let binary_name = hook_binary_name();
    let repo_section = build_repo_section(
        options.allowed_repos.as_deref(),
        options.blocked_repos.as_deref(),
    );

    render_template(PRE_PUSH_TEMPLATE, &binary_name, &repo_section, "")
}

pub fn generate_pre_commit_hook(options: &CliOptions) -> String {
    let binary_name = hook_binary_name();
    let exclude_patterns = options
        .exclude
        .as_deref()
        .map(shell_escape)
        .unwrap_or_default();

    render_template(PRE_COMMIT_TEMPLATE, &binary_name, "", &exclude_patterns)
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
