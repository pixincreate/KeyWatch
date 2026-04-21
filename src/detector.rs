use regex::Regex;
use serde::Deserialize;
use std::fs;

/// Represents a secret detector used in scanning.
pub struct Detector {
    pub name: String,
    pub regex: Regex,
    pub finding_type: String,
    pub severity: String,
}

impl Detector {
    pub fn new(
        name: &str,
        pattern: &str,
        finding_type: &str,
        severity: &str,
    ) -> Result<Detector, regex::Error> {
        Ok(Detector {
            name: name.to_string(),
            regex: Regex::new(pattern)?,
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
        })
    }
}

/// This structure mirrors the detectors.toml file layout.
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
}

fn find_detectors_config() -> Result<std::path::PathBuf, String> {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let config_path = exe_dir.join("detectors.toml");
            if config_path.exists() {
                return Ok(config_path);
            }
        }
    }
    Ok(std::path::PathBuf::from("detectors.toml"))
}

/// initialize_detectors reads the detector definitions from detectors.toml and returns a vector of Detector.
pub fn initialize_detectors() -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    let config_path = find_detectors_config()?;
    let toml_contents = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;

    let config: DetectorsConfig = toml::from_str(&toml_contents)
        .map_err(|e| format!("Failed to parse detectors.toml: {}", e))?;

    Ok(config
        .detectors
        .into_iter()
        .map(|det| Detector::new(&det.name, &det.pattern, &det.finding_type, &det.severity))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Invalid detector pattern: {}", e))?)
}
