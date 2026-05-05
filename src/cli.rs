use clap::{ArgGroup, Parser};

/// KeyWatch: A secret scanner for your files and directories.
#[derive(Parser, Debug)]
#[command(author, version, about = "Scan files and directories for secrets", long_about = None)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(&["file", "dir", "install_hook", "uninstall_hook", "init"]),
))]
#[command(group(
    ArgGroup::new("hook_action")
        .multiple(false)
        .args(&["install_hook", "uninstall_hook"]),
))]
pub struct CliOptions {
    /// Scan specific file(s) - supports multiple --file flags
    /// Example: --file file1.txt --file file2.txt
    #[arg(short, long, alias = "files")]
    pub file: Vec<String>,

    /// Scan all files in a directory (scans recursively)
    #[arg(short, long)]
    pub dir: Option<String>,

    /// Output the result to a file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Print the scan results to the console
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Allowed repository URLs (comma-separated)
    /// Experimental: Push to these repos will be allowed
    #[arg(long)]
    pub allowed_repos: Option<String>,

    /// Blocked repository URLs (comma-separated)
    /// Experimental: Push to these repos will be blocked
    #[arg(long)]
    pub blocked_repos: Option<String>,

    /// Paths to exclude from scanning (comma-separated, supports glob patterns)
    #[arg(long)]
    pub exclude: Option<String>,

    /// Install KeyWatch as a git hook
    /// Options: pre-push, pre-commit
    #[arg(long, value_parser = ["pre-push", "pre-commit"], conflicts_with = "uninstall_hook")]
    pub install_hook: Option<String>,

    /// Remove a KeyWatch git hook
    /// Options: pre-push, pre-commit
    #[arg(long, value_parser = ["pre-push", "pre-commit"], conflicts_with = "install_hook")]
    pub uninstall_hook: Option<String>,

    /// Install the selected hook globally using git core.hooksPath
    #[arg(
        long,
        conflicts_with_all = ["file", "dir", "init"],
        requires = "hook_action",
        default_value_t = false
    )]
    pub global: bool,

    /// Print shell aliases for keywatch and kw
    #[arg(long, value_parser = ["bash", "zsh", "fish", "posix"])]
    pub init: Option<String>,

    /// Exit code behavior
    /// Options:
    ///   - always: Always exit 0 (bypass)
    ///   - critical: Exit 0 if only LOW/MEDIUM severity
    ///   - strict: Exit non-zero for any finding (default)
    #[arg(long, default_value = "strict")]
    pub exit_mode: String,

    /// Verify binary integrity on startup
    #[arg(long, default_value_t = false)]
    pub verify_integrity: bool,
}
