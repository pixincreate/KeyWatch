use crate::detector::Detector;
use crate::detector::DetectorError;
use crate::report::Severity;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// User-facing configuration that extends and overrides the built-in detectors.
///
/// Loaded from `--config <path>` or discovered by walking up from the first
/// CLI scan path (the directory itself, or a file's parent) through its
/// ancestors, stopping at the enclosing repository root or the home
/// directory. Merges with `detectors.toml`: custom rules are appended,
/// overrides are applied by detector name.
#[derive(Deserialize, Default)]
pub struct KeywatchConfig {
    pub rules: Option<Vec<CustomRule>>,
    pub overrides: Option<HashMap<String, DetectorOverride>>,
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    CurrentDirectory {
        source: std::io::Error,
    },
    NotFound {
        path: String,
    },
    Read {
        path: String,
        source: std::io::Error,
    },
    Invalid {
        source: toml::de::Error,
    },
    CustomRule {
        name: String,
        source: DetectorError,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::CurrentDirectory { source } => {
                write!(
                    formatter,
                    "Failed to determine current directory: {}",
                    source
                )
            }
            ConfigError::NotFound { path } => {
                write!(formatter, "Config file not found: '{}'", path)
            }
            ConfigError::Read { path, source } => {
                write!(formatter, "Failed to read config '{}': {}", path, source)
            }
            ConfigError::Invalid { source } => write!(formatter, "Invalid config: {}", source),
            ConfigError::CustomRule { name, source } => {
                write!(formatter, "custom rule '{}': {}", name, source)
            }
        }
    }
}

impl StdError for ConfigError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ConfigError::CurrentDirectory { source } => Some(source),
            ConfigError::NotFound { .. } => None,
            ConfigError::Read { source, .. } => Some(source),
            ConfigError::Invalid { source } => Some(source),
            ConfigError::CustomRule { source, .. } => Some(source),
        }
    }
}

impl KeywatchConfig {
    /// Validate then apply this config to a detector set.
    ///
    /// All custom detectors are built in a scratch buffer first; on any error
    /// the passed-in vector is left untouched (fail-closed / transactional).
    pub fn apply_to(&self, detectors: &mut Vec<Detector>) -> Result<(), ConfigError> {
        // Phase 1 — validate: build every new detector before touching `detectors`.
        let mut staged_detectors: Vec<Detector> = Vec::new();
        if let Some(rules) = &self.rules {
            for rule in rules {
                let detector = Detector::new(
                    &rule.name,
                    &rule.pattern,
                    &rule.finding_type,
                    rule.severity.as_str(),
                    &[],
                    &[],
                    None,
                )
                .map_err(|source| ConfigError::CustomRule {
                    name: rule.name.clone(),
                    source,
                })?;
                staged_detectors.push(detector);
            }
        }

        // Phase 2 — commit: all validation passed, mutate.
        detectors.extend(staged_detectors);

        if let Some(overrides) = &self.overrides {
            detectors.retain(|detector| match overrides.get(&detector.name) {
                Some(detector_override) => detector_override.enabled != Some(false),
                None => true,
            });
            for detector in detectors.iter_mut() {
                if let Some(severity) = overrides
                    .get(&detector.name)
                    .and_then(|detector_override| detector_override.severity)
                {
                    detector.severity = severity;
                }
            }
        }

        Ok(())
    }

    /// Load config with scan-path-aware discovery.
    ///
    /// Resolution order:
    /// 1. `explicit_path` — used as-is; returns `Err` if the file is absent.
    /// 2. First CLI scan path — the directory itself for a directory, or the
    ///    parent for a file — then each ancestor directory, nearest first.
    /// 3. Current working directory (and its ancestors) — only when
    ///    `scan_paths` is empty.
    ///
    /// The ancestor walk stops at the first directory containing `.git` (the
    /// repository root) or at the home directory, so configuration is never
    /// read from outside the tree being scanned.
    ///
    /// Candidate filenames tried in order: `.keywatch.toml`, `keywatch.toml`,
    /// `.kw.toml`.
    pub fn load_for_paths(
        explicit_path: Option<&str>,
        scan_paths: &[String],
    ) -> Result<Option<Self>, ConfigError> {
        let cwd =
            std::env::current_dir().map_err(|source| ConfigError::CurrentDirectory { source })?;
        Self::load_for_paths_at_cwd(explicit_path, scan_paths, &cwd)
    }

    fn load_for_paths_at_cwd(
        explicit_path: Option<&str>,
        scan_paths: &[String],
        cwd: &Path,
    ) -> Result<Option<Self>, ConfigError> {
        let config_path = match explicit_path {
            Some(path) if !Path::new(path).exists() => {
                return Err(ConfigError::NotFound {
                    path: path.to_string(),
                });
            }
            Some(path) => Some(path.to_string()),
            None => find_config_candidates(scan_paths, cwd),
        };

        let Some(config_path) = config_path else {
            return Ok(None);
        };

        let contents = fs::read_to_string(&config_path).map_err(|source| ConfigError::Read {
            path: config_path.clone(),
            source,
        })?;

        toml::from_str(&contents)
            .map(Some)
            .map_err(|source| ConfigError::Invalid { source })
    }
}

#[derive(Deserialize, Clone)]
pub struct CustomRule {
    pub name: String,
    pub pattern: String,
    pub finding_type: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[allow(dead_code)]
    pub description: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct DetectorOverride {
    pub enabled: Option<bool>,
    pub severity: Option<Severity>,
}

fn default_severity() -> Severity {
    Severity::Medium
}

/// Candidate filenames tried in order when auto-discovering a config file.
const CONFIG_NAMES: [&str; 3] = [".keywatch.toml", "keywatch.toml", ".kw.toml"];

fn find_config_candidates(scan_paths: &[String], cwd: &Path) -> Option<String> {
    find_file_upwards(scan_paths, cwd, &CONFIG_NAMES)
}

/// Walks up from the first scan path (or `cwd`) looking for one of `names`,
/// nearest directory first, stopping at the repository root or the home
/// directory so nothing outside the scanned tree's trust boundary is used.
/// Shared by config discovery and baseline discovery.
pub(crate) fn find_file_upwards(
    scan_paths: &[String],
    cwd: &Path,
    names: &[&str],
) -> Option<String> {
    let search_dir: PathBuf = match scan_paths.first() {
        Some(first) => {
            let scan_path = Path::new(first);
            if scan_path.is_dir() {
                scan_path.to_path_buf()
            } else {
                scan_path
                    .parent()
                    .map(Path::to_path_buf)
                    .filter(|parent| parent != Path::new(""))
                    .unwrap_or_else(|| PathBuf::from("."))
            }
        }
        None => cwd.to_path_buf(),
    };

    let search_dir = if search_dir.is_absolute() {
        search_dir
    } else {
        cwd.join(search_dir)
    };
    // Drop "." components so discovered paths read as "/repo/.keywatch.toml"
    // rather than "/repo/./.keywatch.toml" when reported to the user.
    let search_dir: PathBuf = search_dir
        .components()
        .filter(|component| !matches!(component, std::path::Component::CurDir))
        .collect();

    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);

    for dir in search_dir.ancestors() {
        let found = names
            .iter()
            .map(|name| dir.join(name))
            .find(|candidate_path| candidate_path.exists())
            .and_then(|candidate_path| candidate_path.to_str().map(str::to_string));
        if let Some(config_path) = found {
            // A world-writable directory is not a trust boundary: on a shared
            // host any user could drop a config into /tmp and weaken every
            // scan beneath it. Neither is a world-writable config file: it
            // can be rewritten in place even inside a 0755 directory.
            if is_world_writable(dir) || is_world_writable(Path::new(&config_path)) {
                return None;
            }
            return Some(config_path);
        }
        if dir.join(".git").exists() || home.as_deref() == Some(dir) {
            return None;
        }
    }
    None
}

#[cfg(unix)]
fn is_world_writable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o002 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_world_writable(_path: &Path) -> bool {
    false
}
