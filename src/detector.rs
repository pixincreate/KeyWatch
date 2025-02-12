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
    pub fn new(name: &str, pattern: &str, finding_type: &str, severity: &str) -> Detector {
        Detector {
            name: name.to_string(),
            regex: Regex::new(pattern).unwrap(),
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
        }
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

/// initialize_detectors reads the detector definitions from detectors.toml and returns a vector of Detector.
/// You can adjust the path to the TOML file as needed.
pub fn initialize_detectors() -> Vec<Detector> {
    let toml_contents = fs::read_to_string("detectors.toml")
        .expect("Failed to read detectors.toml configuration file");

    let config: DetectorsConfig =
        toml::from_str(&toml_contents).expect("Failed to parse detectors.toml");

    config
        .detectors
        .into_iter()
        .map(|det| Detector::new(&det.name, &det.pattern, &det.finding_type, &det.severity))
        .collect()
}
