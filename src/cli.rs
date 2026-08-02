use clap::{Args, Parser, Subcommand, ValueEnum};

/// KeyWatch: A secret scanner for your files and directories.
#[derive(Parser, Debug)]
#[command(author, version, about = "Scan files and directories for secrets", long_about = None)]
pub struct CliOptions {
    #[command(subcommand)]
    pub command: Command,
}

impl CliOptions {
    pub fn validate(&self) -> Result<(), String> {
        match &self.command {
            Command::Scan(args) => args.validate(),
            Command::Hook(args) => args.validate(),
            _ => Ok(()),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan files or directories
    Scan(ScanArgs),

    /// Manage KeyWatch git hooks
    Hook(HookArgs),

    /// Print shell aliases for keywatch and kw
    Init {
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Verify binary integrity
    VerifyIntegrity,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Paths to scan (files or directories)
    pub paths: Vec<String>,

    /// Read input from stdin instead of files
    #[arg(long, default_value_t = false)]
    pub stdin: bool,

    /// Scan git history instead of files
    #[arg(long, default_value_t = false)]
    pub git_history: bool,

    /// Output the result to a file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Print the scan results to the console
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Paths to exclude from scanning (comma-separated, supports glob patterns)
    #[arg(long)]
    pub exclude: Option<String>,

    /// Exit code behavior
    #[arg(long, value_enum, default_value_t = ExitMode::Strict)]
    pub exit_mode: ExitMode,

    /// Path to a baseline file for suppressing known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Update the baseline file with current findings instead of scanning
    #[arg(long)]
    pub update_baseline: bool,
}

impl ScanArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.git_history {
            if self.stdin {
                return Err("Cannot specify both --git-history and --stdin".to_string());
            }
            if self.paths.len() > 1 {
                return Err("Cannot specify more than one path with --git-history".to_string());
            }
            return Ok(());
        }
        if self.stdin && !self.paths.is_empty() {
            return Err("Cannot specify both --stdin and paths".to_string());
        }
        if !self.stdin && self.paths.is_empty() {
            return Err("Must specify paths, use --stdin, or use --git-history".to_string());
        }
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct HookArgs {
    #[command(subcommand)]
    pub action: HookAction,
}

impl HookArgs {
    fn validate(&self) -> Result<(), String> {
        match &self.action {
            HookAction::Install(args) => args.validate(),
            HookAction::Uninstall(_) => Ok(()),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum HookAction {
    /// Install a KeyWatch git hook
    Install(HookInstallArgs),

    /// Remove a KeyWatch git hook
    Uninstall(HookUninstallArgs),
}

#[derive(Args, Debug)]
pub struct HookInstallArgs {
    /// Type of hook to install
    #[arg(value_enum)]
    pub hook_type: HookType,

    /// Install the hook globally using git core.hooksPath
    #[arg(long, default_value_t = false)]
    pub global: bool,

    /// Allowed repository URLs (comma-separated) - pre-push only
    #[arg(long)]
    pub allowed_repos: Option<String>,

    /// Blocked repository URLs (comma-separated) - pre-push only
    #[arg(long)]
    pub blocked_repos: Option<String>,

    /// Paths to exclude from scanning - pre-commit only
    #[arg(long)]
    pub exclude: Option<String>,
}

impl HookInstallArgs {
    fn validate(&self) -> Result<(), String> {
        match self.hook_type {
            HookType::PreCommit => {
                if self.allowed_repos.is_some() || self.blocked_repos.is_some() {
                    return Err(
                        "--allowed-repos and --blocked-repos are only supported for pre-push hooks"
                            .to_string(),
                    );
                }
            }
            HookType::PrePush => {
                if self.exclude.is_some() {
                    return Err("--exclude is only supported for pre-commit hooks".to_string());
                }
            }
        }

        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct HookUninstallArgs {
    /// Type of hook to remove
    #[arg(value_enum)]
    pub hook_type: HookType,

    /// Remove the hook globally from git core.hooksPath
    #[arg(long, default_value_t = false)]
    pub global: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum HookType {
    PreCommit,
    PrePush,
}

impl HookType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreCommit => "pre-commit",
            Self::PrePush => "pre-push",
        }
    }
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Posix,
}

impl Shell {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Posix => "posix",
        }
    }
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum ExitMode {
    Always,
    Critical,
    Strict,
}

impl ExitMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Critical => "critical",
            Self::Strict => "strict",
        }
    }
}
