use crate::config::ConfigError;
use crate::detector::DetectorInitError;
use thiserror::Error;
use std::io;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScannerError {
    #[error("{source}")]
    DetectorInit { source: DetectorInitError },
    #[error("{source}")]
    Config { source: ConfigError },
    #[error("Read error on {path}: {source}")]
    ReadStream {
        path: String,
        source: io::Error,
    },
    #[error("Failed to run git log: {source}")]
    RunGitLog { source: io::Error },
    #[error("Failed to run git diff: {source}")]
    RunGitDiff { source: io::Error },
    #[error("Failed to capture git stdout")]
    CaptureGitStdout,
    #[error("git process error: {source}")]
    GitProcess { source: io::Error },
    #[error("git log exited with non-zero status")]
    GitLogNonZero,
    #[error("git diff exited with non-zero status")]
    GitDiffNonZero,
    #[error("Invalid exclude pattern '{pattern}': {source}")]
    InvalidExcludePattern {
        pattern: String,
        source: glob::PatternError,
    },
    #[error("Invalid config exclude pattern '{pattern}': {source}")]
    InvalidConfigExcludePattern {
        pattern: String,
        source: glob::PatternError,
    },
}
