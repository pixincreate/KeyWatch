use super::DetectorError;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DetectorInitError {
    #[error("Failed to locate detectors.toml")]
    ConfigNotFound,
    #[error("Failed to read {}: {source}", path.display())]
    ReadConfig { path: PathBuf, source: io::Error },
    #[error("Failed to parse detectors.toml: {source}")]
    ParseConfig { source: toml::de::Error },
    #[error("duplicate detector name '{detector}'")]
    DuplicateName { detector: String },
    #[error("{source}")]
    InvalidDetector { source: DetectorError },
}
