mod error;

pub use error::DetectorInitError;

use crate::report::{ParseSeverityError, Severity};
use regex::Regex;
use serde::Deserialize;
use std::{borrow::Cow, fs, str::FromStr};
use thiserror::Error;

const EMBEDDED_DETECTORS_CONFIG: &str = include_str!("../detectors.toml");

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error("invalid pattern in detector '{detector}': {source}")]
    InvalidPattern {
        detector: String,
        source: regex::Error,
    },
    #[error("invalid allowlist pattern in detector '{detector}': {source}")]
    InvalidAllowlistPattern {
        detector: String,
        source: regex::Error,
    },
    #[error("invalid severity in detector '{detector}': {source}")]
    InvalidSeverity {
        detector: String,
        source: ParseSeverityError,
    },
    #[error("invalid validator in detector '{detector}': {source}")]
    InvalidValidator {
        detector: String,
        source: ParseValidatorError,
    },
}

/// Extra structural check a detector can require of its matches, for
/// patterns whose shape alone is too permissive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentValidator {
    /// Payment card numbers carry a Luhn check digit. Without it, a 13-16
    /// digit pattern matches every commit hash fragment, timestamp and
    /// numeric id in a codebase.
    Luhn,
}

impl FromStr for ContentValidator {
    type Err = ParseValidatorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().as_str() {
            "luhn" => Ok(Self::Luhn),
            other => Err(ParseValidatorError {
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Error)]
#[error("unknown validator '{value}'")]
pub struct ParseValidatorError {
    value: String,
}

/// Luhn checksum, ignoring embedded separators.
fn passes_luhn(matched: &str) -> bool {
    let digits: Vec<u32> = matched.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| match index % 2 {
            1 if *digit > 4 => digit * 2 - 9,
            1 => digit * 2,
            _ => *digit,
        })
        .sum();
    sum % 10 == 0
}

pub struct Detector {
    pub name: String,
    pub regex: Regex,
    pub finding_type: String,
    pub severity: Severity,
    pub allowlist: Vec<Regex>,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
    pub validator: Option<ContentValidator>,
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
            keywords: keywords
                .iter()
                .map(|keyword| keyword.to_lowercase())
                .collect(),
            entropy_threshold,
            validator: None,
        })
    }

    /// Attaches a structural validator. Kept separate from `new` so adding a
    /// check does not touch every construction site.
    pub fn with_validator(mut self, validator: Option<ContentValidator>) -> Self {
        self.validator = validator;
        self
    }

    /// Whether a match satisfies the detector's structural validator.
    pub fn passes_validation(&self, matched: &str) -> bool {
        match self.validator {
            Some(ContentValidator::Luhn) => passes_luhn(matched),
            None => true,
        }
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

    /// Whether a regex match clears every detector gate — allowlist, entropy
    /// and the structural validator. The scanner loops and the tests share
    /// this so the accept chain exists in exactly one place.
    pub fn accepts_match(&self, matched: &str) -> bool {
        !self
            .allowlist
            .iter()
            .any(|pattern| pattern.is_match(matched))
            && self.has_sufficient_entropy(matched)
            && self.passes_validation(matched)
    }

    /// Whether the pattern carries the dot-matches-newline flag anywhere —
    /// `(?s)` or the grouped `(?s:...)` form — and must therefore run per
    /// chunk instead of per line, or multiline secrets slip past it. Single
    /// source for the production partition and the tests.
    pub fn is_multiline(&self) -> bool {
        self.regex.as_str().contains("(?s")
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
    validate: Option<String>,
}

/// True when `path` sits inside `dir`, i.e. the scanned repository supplied
/// it rather than the operator.
fn is_within(path: &std::path::Path, dir: &std::path::Path) -> bool {
    match (fs::canonicalize(path), fs::canonicalize(dir)) {
        (Ok(path), Ok(dir)) => path.starts_with(dir),
        _ => false,
    }
}

/// Highest directory whose contents the scanned tree's owner controls: the
/// enclosing repository root when the target sits inside one, otherwise the
/// target directory itself. A repository that reaches `KEYWATCH_CONFIG_PATH`
/// through `.envrc`/direnv or a devcontainer can point it anywhere in this
/// subtree, so nothing inside it can be trusted in trusted mode.
pub(crate) fn untrusted_root(scan_path: &str, cwd: &std::path::Path) -> std::path::PathBuf {
    let path = std::path::Path::new(scan_path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let start = if absolute.is_dir() {
        absolute
    } else {
        absolute
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| cwd.to_path_buf())
    };

    for dir in start.ancestors().skip(1) {
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
    }
    start
}

fn find_detectors_config(
    include_repository_config: bool,
    untrusted_roots: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    std::env::var("KEYWATCH_CONFIG_PATH")
        .map(std::path::PathBuf::from)
        .ok()
        .filter(|path| path.exists())
        // KEYWATCH_CONFIG_PATH is an operator channel. A repository can reach
        // it through .envrc/direnv or a devcontainer, so in trusted mode a
        // a value pointing back into the tree being scanned — at or below any
        // untrusted root — is ignored.
        .filter(|path| {
            include_repository_config
                || untrusted_roots.is_empty()
                || !untrusted_roots.iter().any(|root| is_within(path, root))
        })
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
    initialize_detectors_from_config(true, &[])
}

pub(crate) fn initialize_trusted_detectors(
    untrusted_roots: &[std::path::PathBuf],
) -> Result<Vec<Detector>, DetectorInitError> {
    initialize_detectors_from_config(false, untrusted_roots)
}

fn initialize_detectors_from_config(
    include_repository_config: bool,
    untrusted_roots: &[std::path::PathBuf],
) -> Result<Vec<Detector>, DetectorInitError> {
    let toml_contents = match find_detectors_config(include_repository_config, untrusted_roots) {
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
            let validator = detector_config
                .validate
                .as_deref()
                .map(ContentValidator::from_str)
                .transpose()
                .map_err(|source| DetectorError::InvalidValidator {
                    detector: detector_config.name.clone(),
                    source,
                })?;
            Detector::new(
                &detector_config.name,
                &detector_config.pattern,
                &detector_config.finding_type,
                &detector_config.severity,
                allowlist,
                keywords,
                detector_config.entropy,
            )
            .map(|detector| detector.with_validator(validator))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| DetectorInitError::InvalidDetector { source })
}
