use crate::config::ConfigError;
use crate::detector::DetectorInitError;
use std::error::Error as StdError;
use std::{fmt, io};

#[derive(Debug)]
#[non_exhaustive]
pub enum ScannerError {
    DetectorInit {
        source: DetectorInitError,
    },
    Config {
        source: ConfigError,
    },
    ReadStream {
        path: String,
        source: io::Error,
    },
    RunGitLog {
        source: io::Error,
    },
    RunGitDiff {
        source: io::Error,
    },
    CaptureGitStdout,
    GitProcess {
        source: io::Error,
    },
    GitLogNonZero,
    GitDiffNonZero,
    InvalidExcludePattern {
        pattern: String,
        source: glob::PatternError,
    },
    InvalidConfigExcludePattern {
        pattern: String,
        source: glob::PatternError,
    },
}

impl fmt::Display for ScannerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::DetectorInit { source } => write!(formatter, "{}", source),
            ScannerError::Config { source } => write!(formatter, "{}", source),
            ScannerError::ReadStream { path, source } => {
                write!(formatter, "Read error on {}: {}", path, source)
            }
            ScannerError::RunGitLog { source } => {
                write!(formatter, "Failed to run git log: {}", source)
            }
            ScannerError::RunGitDiff { source } => {
                write!(formatter, "Failed to run git diff: {}", source)
            }
            ScannerError::CaptureGitStdout => write!(formatter, "Failed to capture git stdout"),
            ScannerError::GitProcess { source } => {
                write!(formatter, "git process error: {}", source)
            }
            ScannerError::GitLogNonZero => write!(formatter, "git log exited with non-zero status"),
            ScannerError::GitDiffNonZero => {
                write!(formatter, "git diff exited with non-zero status")
            }
            ScannerError::InvalidExcludePattern { pattern, source } => {
                write!(
                    formatter,
                    "Invalid exclude pattern '{}': {}",
                    pattern, source
                )
            }
            ScannerError::InvalidConfigExcludePattern { pattern, source } => write!(
                formatter,
                "Invalid config exclude pattern '{}': {}",
                pattern, source
            ),
        }
    }
}

impl StdError for ScannerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ScannerError::DetectorInit { source } => Some(source),
            ScannerError::Config { source } => Some(source),
            ScannerError::ReadStream { source, .. } => Some(source),
            ScannerError::RunGitLog { source } | ScannerError::RunGitDiff { source } => {
                Some(source)
            }
            ScannerError::CaptureGitStdout
            | ScannerError::GitLogNonZero
            | ScannerError::GitDiffNonZero => None,
            ScannerError::GitProcess { source } => Some(source),
            ScannerError::InvalidExcludePattern { source, .. }
            | ScannerError::InvalidConfigExcludePattern { source, .. } => Some(source),
        }
    }
}
