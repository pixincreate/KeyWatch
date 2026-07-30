use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

/// User-facing configuration that extends and overrides the built-in detectors.
///
/// Loaded from `--config <path>` or `.keywatch.toml` in the scan root.
/// Merges with `detectors.toml`: custom rules are appended, overrides are
/// applied by detector name.
#[derive(Deserialize, Default)]
pub struct KeywatchConfig {
    /// Additional detectors beyond those in detectors.toml
    pub rules: Option<Vec<CustomRule>>,
    /// Per-detector overrides (by name)
    pub overrides: Option<HashMap<String, DetectorOverride>>,
    /// Extra exclude patterns (merged with --exclude CLI flag)
    pub exclude: Option<Vec<String>>,
}

#[derive(Deserialize, Clone)]
pub struct CustomRule {
    pub name: String,
    pub pattern: String,
    pub finding_type: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[allow(dead_code)]
    pub description: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct DetectorOverride {
    pub enabled: Option<bool>,
    pub severity: Option<String>,
}

fn default_severity() -> String {
    "MEDIUM".to_string()
}

impl KeywatchConfig {
    /// Load config from the given path. Returns None if the file doesn't exist
    /// (config is optional).
    pub fn load(path: Option<&str>) -> Result<Option<Self>, String> {
        let config_path = match path {
            Some(p) => Some(p.to_string()),
            None => find_config_in_cwd(),
        };

        let config_path = match config_path {
            Some(p) => p,
            None => return Ok(None),
        };

        let contents = fs::read_to_string(&config_path)
            .map_err(|err| format!("Failed to read config '{}': {}", config_path, err))?;

        let config: KeywatchConfig =
            toml::from_str(&contents).map_err(|err| format!("Invalid config: {}", err))?;

        Ok(Some(config))
    }
}

fn find_config_in_cwd() -> Option<String> {
    let candidates = [".keywatch.toml", "keywatch.toml", ".kw.toml"];
    candidates
        .iter()
        .find(|name| std::path::Path::new(name).exists())
        .map(|&name| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"
[[rules]]
name = "TestDetector"
pattern = "\\bTEST_SECRET_[A-Z]+\\b"
finding_type = "Test Secret"
severity = "HIGH"
"#;
        let config: KeywatchConfig = toml::from_str(toml_str).expect("should parse");
        assert!(config.rules.is_some());
        assert_eq!(config.rules.as_ref().unwrap().len(), 1);
        assert_eq!(config.rules.as_ref().unwrap()[0].name, "TestDetector");
        assert!(config.overrides.is_none());
    }

    #[test]
    fn test_parse_config_with_overrides() {
        let toml_str = r#"
[overrides]
AWSKeyDetector = { enabled = false }
GitHubTokenDetector = { severity = "CRITICAL" }
"#;
        let config: KeywatchConfig = toml::from_str(toml_str).expect("should parse");
        let overrides = config.overrides.expect("overrides present");
        assert_eq!(overrides.len(), 2);

        let aws = overrides.get("AWSKeyDetector").expect("found");
        assert_eq!(aws.enabled, Some(false));
        assert!(aws.severity.is_none());

        let gh = overrides.get("GitHubTokenDetector").expect("found");
        assert_eq!(gh.severity.as_deref(), Some("CRITICAL"));
        assert!(gh.enabled.is_none());
    }

    #[test]
    fn test_empty_config_is_default() {
        let toml_str = "";
        let config: KeywatchConfig = toml::from_str(toml_str).expect("empty should parse");
        assert!(config.rules.is_none());
        assert!(config.overrides.is_none());
        assert!(config.exclude.is_none());
    }
}
