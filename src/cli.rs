use clap::{ArgGroup, Parser};

/// KeyWatch: A secret scanner for your files and directories.
#[derive(Parser, Debug)]
#[command(author, version, about = "Scan files and directories for secrets", long_about = None)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(&["file", "dir", "install_hook"]),
))]
pub struct CliOptions {
    /// Scan a single file
    #[arg(short, long)]
    pub file: Option<String>,

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
    #[arg(long, value_parser = ["pre-push", "pre-commit"])]
    pub install_hook: Option<String>,

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
