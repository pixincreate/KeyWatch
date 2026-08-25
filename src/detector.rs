mod error;

pub use error::DetectorInitError;

use crate::report::{ParseSeverityError, Severity};
use regex::Regex;
use serde::Deserialize;
use std::{borrow::Cow, fmt, fs, str::FromStr};

const EMBEDDED_DETECTORS_CONFIG: &str = include_str!("../detectors.toml");

#[derive(Debug)]
pub enum DetectorError {
    InvalidPattern {
        detector: String,
        source: regex::Error,
    },
    InvalidAllowlistPattern {
        detector: String,
        source: regex::Error,
    },
    InvalidSeverity {
        detector: String,
        source: ParseSeverityError,
    },
}

impl fmt::Display for DetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectorError::InvalidPattern { detector, source } => {
                write!(
                    formatter,
                    "invalid pattern in detector '{}': {}",
                    detector, source
                )
            }
            DetectorError::InvalidAllowlistPattern { detector, source } => {
                write!(
                    formatter,
                    "invalid allowlist pattern in detector '{}': {}",
                    detector, source
                )
            }
            DetectorError::InvalidSeverity { detector, source } => {
                write!(
                    formatter,
                    "invalid severity in detector '{}': {}",
                    detector, source
                )
            }
        }
    }
}

impl std::error::Error for DetectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPattern { source, .. } | Self::InvalidAllowlistPattern { source, .. } => {
                Some(source)
            }
            Self::InvalidSeverity { source, .. } => Some(source),
        }
    }
}

pub struct Detector {
    pub name: String,
    pub regex: Regex,
    pub finding_type: String,
    pub severity: Severity,
    pub allowlist: Vec<Regex>,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
}

impl Detector {
    pub fn new(
        name: &str,
        pattern: &str,
        finding_type: &str,
        severity: &str,
        allowlist: &[String],
        keywords: &[String],
        entropy_threshold: Option<f64>,
    ) -> Result<Detector, DetectorError> {
        let regex = Regex::new(pattern).map_err(|source| DetectorError::InvalidPattern {
            detector: name.to_string(),
            source,
        })?;

        let parsed_severity =
            Severity::from_str(severity).map_err(|source| DetectorError::InvalidSeverity {
                detector: name.to_string(),
                source,
            })?;

        let mut compiled_allowlist = Vec::new();
        for pattern in allowlist {
            let compiled =
                Regex::new(pattern).map_err(|source| DetectorError::InvalidAllowlistPattern {
                    detector: name.to_string(),
                    source,
                })?;
            compiled_allowlist.push(compiled);
        }

        Ok(Detector {
            name: name.to_string(),
            regex,
            finding_type: finding_type.to_string(),
            severity: parsed_severity,
            allowlist: compiled_allowlist,
            keywords: keywords.iter().map(|keyword| keyword.to_lowercase()).collect(),
            entropy_threshold,
        })
    }

    /// `lowercase_content` must already be lowercased. Keywords are stored
    /// lowercased at construction so callers can lowercase once per line
    /// instead of once per detector.
    pub fn has_keywords(&self, lowercase_content: &str) -> bool {
        if self.keywords.is_empty() {
            return true;
        }
        self.keywords
            .iter()
            .any(|keyword| lowercase_content.contains(keyword.as_str()))
    }

    pub fn has_sufficient_entropy(&self, matched: &str) -> bool {
        match self.entropy_threshold {
            Some(threshold) => shannon_entropy(matched) >= threshold,
            None => true,
        }
    }
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for character in input.chars() {
        *counts.entry(character).or_insert(0) += 1;
    }
    let input_length = input.len() as f64;
    counts.values().fold(0.0, |entropy, &count| {
        let probability = count as f64 / input_length;
        entropy - probability * probability.log2()
    })
}

#[derive(Deserialize)]
struct DetectorsConfig {
    detectors: Vec<DetectorConfig>,
}

#[derive(Deserialize)]
struct DetectorConfig {
    name: String,
    pattern: String,
    finding_type: String,
    severity: String,
    allowlist: Option<Vec<String>>,
    keywords: Option<Vec<String>>,
    entropy: Option<f64>,
}

fn find_detectors_config(include_repository_config: bool) -> Option<std::path::PathBuf> {
    std::env::var("KEYWATCH_CONFIG_PATH")
        .map(std::path::PathBuf::from)
        .ok()
        .filter(|path| path.exists())
        .or_else(|| {
            if !include_repository_config {
                return None;
            }

            let repository_config = std::path::PathBuf::from("detectors.toml");
            repository_config.exists().then_some(repository_config)
        })
        .or_else(|| {
            dirs::config_dir()
                .map(|config_directory| config_directory.join("keywatch").join("detectors.toml"))
                .filter(|path| path.exists())
        })
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|executable_path| {
                    executable_path
                        .parent()
                        .map(|directory| directory.join("detectors.toml"))
                })
                .filter(|path| path.exists())
        })
}

pub fn initialize_detectors() -> Result<Vec<Detector>, DetectorInitError> {
    initialize_detectors_from_config(true)
}

pub(crate) fn initialize_trusted_detectors() -> Result<Vec<Detector>, DetectorInitError> {
    initialize_detectors_from_config(false)
}

fn initialize_detectors_from_config(
    include_repository_config: bool,
) -> Result<Vec<Detector>, DetectorInitError> {
    let toml_contents = match find_detectors_config(include_repository_config) {
        Some(config_path) => Cow::Owned(fs::read_to_string(&config_path).map_err(|source| {
            DetectorInitError::ReadConfig {
                path: config_path,
                source,
            }
        })?),
        None => Cow::Borrowed(EMBEDDED_DETECTORS_CONFIG),
    };

    let config: DetectorsConfig = toml::from_str(&toml_contents)
        .map_err(|source| DetectorInitError::ParseConfig { source })?;

    let mut seen_names = std::collections::HashSet::new();
    for detector_config in &config.detectors {
        if !seen_names.insert(detector_config.name.as_str()) {
            return Err(DetectorInitError::DuplicateName {
                detector: detector_config.name.clone(),
            });
        }
    }

    config
        .detectors
        .into_iter()
        .map(|detector_config| {
            let allowlist = detector_config.allowlist.as_deref().unwrap_or_default();
            let keywords = detector_config.keywords.as_deref().unwrap_or_default();
            Detector::new(
                &detector_config.name,
                &detector_config.pattern,
                &detector_config.finding_type,
                &detector_config.severity,
                allowlist,
                keywords,
                detector_config.entropy,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| DetectorInitError::InvalidDetector { source })
}
