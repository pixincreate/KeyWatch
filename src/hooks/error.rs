use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

#[derive(Debug)]
#[non_exhaustive]
pub enum HookError {
    CreateHookDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    InstallHook {
        path: PathBuf,
        source: std::io::Error,
    },
    MakeHookExecutable {
        path: PathBuf,
        source: std::io::Error,
    },
    CreateGlobalHooksDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    ResolveGitHooksDirectory {
        source: std::io::Error,
    },
    MissingLocalRepository,
    ResolveGitHooksDirectoryFromGit {
        stderr: String,
    },
    EmptyGitHooksDirectory,
    ReadGlobalHooksPath {
        source: std::io::Error,
    },
    ReadGlobalHooksPathFromGit {
        stderr: String,
    },
    MissingGlobalHooksBaseDir,
    ConfigureGlobalHooksPath {
        source: std::io::Error,
    },
    ConfigureGlobalHooksPathWithGit {
        hooks_dir: PathBuf,
        stderr: String,
    },
    InspectExistingHook {
        path: PathBuf,
        source: std::io::Error,
    },
    RefuseExistingHook {
        action: &'static str,
        scope: &'static str,
        path: PathBuf,
    },
    RemoveHook {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl Display for HookError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateHookDirectory { path, source } => write!(
                formatter,
                "Failed to create hook directory '{}': {}",
                path.display(),
                source
            ),
            Self::InstallHook { path, source } => write!(
                formatter,
                "Failed to install hook '{}': {}",
                path.display(),
                source
            ),
            Self::MakeHookExecutable { path, source } => write!(
                formatter,
                "Failed to make hook executable '{}': {}",
                path.display(),
                source
            ),
            Self::CreateGlobalHooksDirectory { path, source } => write!(
                formatter,
                "Failed to create global hooks directory '{}': {}",
                path.display(),
                source
            ),
            Self::ResolveGitHooksDirectory { source } => {
                write!(formatter, "Failed to resolve git hooks directory: {source}")
            }
            Self::MissingLocalRepository => formatter
                .write_str("Local hook installation requires running inside a git repository"),
            Self::ResolveGitHooksDirectoryFromGit { stderr } => {
                write!(formatter, "Failed to resolve git hooks directory: {stderr}")
            }
            Self::EmptyGitHooksDirectory => {
                formatter.write_str("Failed to resolve git hooks directory")
            }
            Self::ReadGlobalHooksPath { source } => {
                write!(
                    formatter,
                    "Failed to read git config core.hooksPath: {source}"
                )
            }
            Self::ReadGlobalHooksPathFromGit { stderr } => write!(
                formatter,
                "Failed to read git config core.hooksPath: {stderr}"
            ),
            Self::MissingGlobalHooksBaseDir => {
                formatter.write_str("Could not determine a directory for global git hooks")
            }
            Self::ConfigureGlobalHooksPath { source } => write!(
                formatter,
                "Failed to configure git global core.hooksPath: {source}"
            ),
            Self::ConfigureGlobalHooksPathWithGit { hooks_dir, stderr } => write!(
                formatter,
                "git config --global core.hooksPath {} failed: {}",
                hooks_dir.display(),
                stderr
            ),
            Self::InspectExistingHook { path, source } => write!(
                formatter,
                "Failed to inspect existing hook '{}': {}",
                path.display(),
                source
            ),
            Self::RefuseExistingHook {
                action,
                scope,
                path,
            } => write!(
                formatter,
                "Refusing to {action} existing {scope} hook at '{}'. Merge it manually or remove it yourself.",
                path.display()
            ),
            Self::RemoveHook { path, source } => write!(
                formatter,
                "Failed to remove hook '{}': {}",
                path.display(),
                source
            ),
        }
    }
}

impl Error for HookError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CreateHookDirectory { source, .. }
            | Self::InstallHook { source, .. }
            | Self::MakeHookExecutable { source, .. }
            | Self::CreateGlobalHooksDirectory { source, .. }
            | Self::ResolveGitHooksDirectory { source }
            | Self::ReadGlobalHooksPath { source }
            | Self::ConfigureGlobalHooksPath { source }
            | Self::InspectExistingHook { source, .. }
            | Self::RemoveHook { source, .. } => Some(source),
            Self::MissingLocalRepository
            | Self::ResolveGitHooksDirectoryFromGit { .. }
            | Self::EmptyGitHooksDirectory
            | Self::ReadGlobalHooksPathFromGit { .. }
            | Self::MissingGlobalHooksBaseDir
            | Self::ConfigureGlobalHooksPathWithGit { .. }
            | Self::RefuseExistingHook { .. } => None,
        }
    }
}
