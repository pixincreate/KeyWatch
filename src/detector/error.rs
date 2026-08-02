use super::DetectorError;
use std::{fmt, io, path::PathBuf};

#[derive(Debug)]
#[non_exhaustive]
pub enum DetectorInitError {
    ConfigNotFound,
    ReadConfig { path: PathBuf, source: io::Error },
    ParseConfig { source: toml::de::Error },
    DuplicateName { detector: String },
    InvalidDetector { source: DetectorError },
}

impl fmt::Display for DetectorInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectorInitError::ConfigNotFound => {
                write!(formatter, "Failed to locate detectors.toml")
            }
            DetectorInitError::ReadConfig { path, source } => {
                write!(formatter, "Failed to read {}: {}", path.display(), source)
            }
            DetectorInitError::ParseConfig { source } => {
                write!(formatter, "Failed to parse detectors.toml: {}", source)
            }
            DetectorInitError::DuplicateName { detector } => {
                write!(formatter, "duplicate detector name '{}'", detector)
            }
            DetectorInitError::InvalidDetector { source } => write!(formatter, "{}", source),
        }
    }
}

impl std::error::Error for DetectorInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DetectorInitError::ConfigNotFound | DetectorInitError::DuplicateName { .. } => None,
            DetectorInitError::ReadConfig { source, .. } => Some(source),
            DetectorInitError::ParseConfig { source } => Some(source),
            DetectorInitError::InvalidDetector { source } => Some(source),
        }
    }
}
