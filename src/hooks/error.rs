use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookError {
    #[error("Failed to create hook directory '{}': {source}", path.display())]
    CreateHookDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to install hook '{}': {source}", path.display())]
    InstallHook {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to make hook executable '{}': {source}", path.display())]
    MakeHookExecutable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to create global hooks directory '{}': {source}", path.display())]
    CreateGlobalHooksDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to resolve git hooks directory: {source}")]
    ResolveGitHooksDirectory { source: std::io::Error },
    #[error("Local hook installation requires running inside a git repository")]
    MissingLocalRepository,
    #[error("Failed to resolve git hooks directory: {stderr}")]
    ResolveGitHooksDirectoryFromGit { stderr: String },
    #[error("Failed to resolve git hooks directory")]
    EmptyGitHooksDirectory,
    #[error("Failed to read git config core.hooksPath: {source}")]
    ReadGlobalHooksPath { source: std::io::Error },
    #[error("Failed to read git config core.hooksPath: {stderr}")]
    ReadGlobalHooksPathFromGit { stderr: String },
    #[error("Could not determine a directory for global git hooks")]
    MissingGlobalHooksBaseDir,
    #[error("Failed to configure git global core.hooksPath: {source}")]
    ConfigureGlobalHooksPath { source: std::io::Error },
    #[error(
        "git config --global core.hooksPath {} failed: {stderr}",
        hooks_dir.display()
    )]
    ConfigureGlobalHooksPathWithGit { hooks_dir: PathBuf, stderr: String },
    #[error("Failed to inspect existing hook '{}': {source}", path.display())]
    InspectExistingHook {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "Refusing to {action} existing {scope} hook at '{}'. Merge it manually or remove it yourself.",
        path.display()
    )]
    RefuseExistingHook {
        action: &'static str,
        scope: &'static str,
        path: PathBuf,
    },
    #[error("Failed to remove hook '{}': {source}", path.display())]
    RemoveHook {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to write output: {source}")]
    WriteOutput { source: std::io::Error },
}
