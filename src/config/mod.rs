use crate::detector::Detector;
use crate::report::Severity;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// User-facing configuration that extends and overrides the built-in detectors.
///
/// Loaded from `--config <path>` or discovered from the first CLI scan path
/// (directory itself, or parent directory for a file path). Merges with
/// `detectors.toml`: custom rules are appended, overrides are applied by
/// detector name.
#[derive(Deserialize, Default)]
pub struct KeywatchConfig {
    pub rules: Option<Vec<CustomRule>>,
    pub overrides: Option<HashMap<String, DetectorOverride>>,
    pub exclude: Option<Vec<String>>,
}

impl KeywatchConfig {
    /// Validate then apply this config to a detector set.
    ///
    /// All custom detectors are built in a scratch buffer first; on any error
    /// the passed-in vector is left untouched (fail-closed / transactional).
    pub fn apply_to(&self, detectors: &mut Vec<Detector>) -> Result<(), String> {
        // Phase 1 — validate: build every new detector before touching `detectors`.
        let mut staged: Vec<Detector> = Vec::new();
        if let Some(rules) = &self.rules {
            for rule in rules {
                let det = Detector::new(
                    &rule.name,
                    &rule.pattern,
                    &rule.finding_type,
                    rule.severity.as_str(),
                    &[],
                    &[],
                    None,
                )
                .map_err(|err| format!("custom rule '{}': {}", rule.name, err))?;
                staged.push(det);
            }
        }

        // Phase 2 — commit: all validation passed, mutate.
        detectors.extend(staged);

        if let Some(overrides) = &self.overrides {
            detectors.retain(|det| match overrides.get(&det.name) {
                Some(ov) => ov.enabled != Some(false),
                None => true,
            });
            for det in detectors.iter_mut() {
                if let Some(sev) = overrides.get(&det.name).and_then(|o| o.severity) {
                    det.severity = sev;
                }
            }
        }

        Ok(())
    }

    /// Load from an explicit path. When `path` is `None`, discovery starts in
    /// the current working directory.
    /// Returns `None` when no config file is found (config is optional).
    pub fn load(path: Option<&str>) -> Result<Option<Self>, String> {
        let cwd = std::env::current_dir()
            .map_err(|err| format!("Failed to determine current directory: {}", err))?;
        Self::load_for_paths_at_cwd(path, &[], &cwd)
    }

    /// Load config with scan-path-aware discovery.
    ///
    /// Resolution order:
    /// 1. `explicit_path` — used as-is; returns `Err` if the file is absent.
    /// 2. First CLI scan path that is a directory — search that directory.
    /// 3. First CLI scan path that is a file — search its parent directory.
    /// 4. Current working directory — only when `scan_paths` is empty.
    ///
    /// Candidate filenames tried in order: `.keywatch.toml`, `keywatch.toml`,
    /// `.kw.toml`.
    pub fn load_for_paths(
        explicit_path: Option<&str>,
        scan_paths: &[String],
    ) -> Result<Option<Self>, String> {
        let cwd = std::env::current_dir()
            .map_err(|err| format!("Failed to determine current directory: {}", err))?;
        Self::load_for_paths_at_cwd(explicit_path, scan_paths, &cwd)
    }

    fn load_for_paths_at_cwd(
        explicit_path: Option<&str>,
        scan_paths: &[String],
        cwd: &Path,
    ) -> Result<Option<Self>, String> {
        let config_path: Option<String> = if let Some(p) = explicit_path {
            if !Path::new(p).exists() {
                return Err(format!("Config file not found: '{}'", p));
            }
            Some(p.to_string())
        } else {
            find_config_candidates(scan_paths, cwd)
        };

        let config_path = match config_path {
            Some(p) => p,
            None => return Ok(None),
        };

        let contents = fs::read_to_string(&config_path)
            .map_err(|err| format!("Failed to read config '{}': {}", config_path, err))?;

        toml::from_str(&contents)
            .map(Some)
            .map_err(|err| format!("Invalid config: {}", err))
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
    let search_dir: PathBuf = match scan_paths.first() {
        Some(first) => {
            let p = Path::new(first);
            if p.is_dir() {
                p.to_path_buf()
            } else {
                p.parent()
                    .map(Path::to_path_buf)
                    .filter(|parent| parent != Path::new(""))
                    .unwrap_or_else(|| PathBuf::from("."))
            }
        }
        None => cwd.to_path_buf(),
    };

    CONFIG_NAMES
        .iter()
        .map(|name| search_dir.join(name))
        .find(|p| p.exists())
        .and_then(|p| p.to_str().map(str::to_string))
}
