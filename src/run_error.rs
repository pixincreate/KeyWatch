use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::io;

use crate::baseline::BaselineError;
use crate::cli::CliValidationError;
use crate::config::ConfigError;
use crate::hooks::HookError;
use crate::scanner::ScannerError;

#[derive(Debug)]
#[non_exhaustive]
pub enum RunCliError {
    Cli { source: CliValidationError },
    Config { source: ConfigError },
    Scanner { source: ScannerError },
    Baseline { source: BaselineError },
    Hooks { source: HookError },
    MissingBaselineForUpdate,
    ReportSerialize { source: serde_json::Error },
    ReportWrite { path: String, source: io::Error },
    ExecutablePath { source: io::Error },
    ExecutableMetadata { source: io::Error },
}

impl Display for RunCliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli { source } => write!(formatter, "{source}"),
            Self::Config { source } => write!(formatter, "{source}"),
            Self::Scanner { source } => write!(formatter, "{source}"),
            Self::Baseline { source } => write!(formatter, "{source}"),
            Self::Hooks { source } => write!(formatter, "{source}"),
            Self::MissingBaselineForUpdate => {
                formatter.write_str("--update-baseline requires --baseline <path>")
            }
            Self::ReportSerialize { source } => {
                write!(formatter, "Failed to serialize report: {source}")
            }
            Self::ReportWrite { path, source } => {
                write!(formatter, "Failed to write report to '{path}': {source}")
            }
            Self::ExecutablePath { source } => {
                write!(formatter, "Failed to get executable path: {source}")
            }
            Self::ExecutableMetadata { source } => {
                write!(formatter, "Failed to get executable metadata: {source}")
            }
        }
    }
}

impl StdError for RunCliError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Cli { source } => Some(source),
            Self::Config { source } => Some(source),
            Self::Scanner { source } => Some(source),
            Self::Baseline { source } => Some(source),
            Self::Hooks { source } => Some(source),
            Self::MissingBaselineForUpdate => None,
            Self::ReportSerialize { source } => Some(source),
            Self::ReportWrite { source, .. } => Some(source),
            Self::ExecutablePath { source } => Some(source),
            Self::ExecutableMetadata { source } => Some(source),
        }
    }
}

impl From<CliValidationError> for RunCliError {
    fn from(source: CliValidationError) -> Self {
        Self::Cli { source }
    }
}

impl From<ConfigError> for RunCliError {
    fn from(source: ConfigError) -> Self {
        Self::Config { source }
    }
}

impl From<ScannerError> for RunCliError {
    fn from(source: ScannerError) -> Self {
        Self::Scanner { source }
    }
}

impl From<BaselineError> for RunCliError {
    fn from(source: BaselineError) -> Self {
        Self::Baseline { source }
    }
}

impl From<HookError> for RunCliError {
    fn from(source: HookError) -> Self {
        Self::Hooks { source }
    }
}
