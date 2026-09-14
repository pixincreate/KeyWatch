use crate::config::ConfigError;
use crate::detector::DetectorInitError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScannerError {
    #[error("{source}")]
    DetectorInit { source: DetectorInitError },
    #[error("{source}")]
    Config { source: ConfigError },
    #[error("Read error on {path}: {source}")]
    ReadStream { path: String, source: io::Error },
    #[error("Failed to run git log: {source}")]
    RunGitLog { source: io::Error },
    #[error("Failed to run git diff: {source}")]
    RunGitDiff { source: io::Error },
    #[error("Failed to run git cat-file: {source}")]
    RunGitCatFile { source: io::Error },
    #[error("Failed to capture git stdout")]
    CaptureGitStdout,
    #[error("git process error: {source}")]
    GitProcess { source: io::Error },
    #[error("git log failed: {stderr}")]
    GitLogNonZero { stderr: String },
    #[error("git diff failed: {stderr}")]
    GitDiffNonZero { stderr: String },
    #[error("Scan path not found: '{path}'")]
    ScanPathMissing { path: String },
    #[error("Cannot read scan path '{path}': {source}")]
    ScanPathUnreadable { path: String, source: io::Error },
    #[error("Scan path '{path}' is a symlink; KeyWatch does not follow symlinks")]
    ScanPathSymlink { path: String },
    #[error("Scan path '{path}' is not a regular file or directory")]
    ScanPathUnsupported { path: String },
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
