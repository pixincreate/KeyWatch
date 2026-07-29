use regex::Regex;
use serde::Deserialize;
use std::fs;

pub struct Detector {
    pub name: String,
    pub regex: Regex,
    pub finding_type: String,
    pub severity: String,
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
    ) -> Result<Detector, String> {
        let regex = Regex::new(pattern)
            .map_err(|err| format!("Invalid pattern in detector '{}': {}", name, err))?;

        let mut compiled_allowlist = Vec::new();
        for pat in allowlist {
            let compiled = Regex::new(pat).map_err(|err| {
                format!("Invalid allowlist pattern in detector '{}': {}", name, err)
            })?;
            compiled_allowlist.push(compiled);
        }

        Ok(Detector {
            name: name.to_string(),
            regex,
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
            allowlist: compiled_allowlist,
            keywords: keywords.to_vec(),
            entropy_threshold,
        })
    }

    pub fn has_keywords(&self, content: &str) -> bool {
        if self.keywords.is_empty() {
            return true;
        }
        let lower = content.to_lowercase();
        self.keywords
            .iter()
            .any(|kw| lower.contains(&kw.to_lowercase()))
    }

    pub fn has_sufficient_entropy(&self, matched: &str) -> bool {
        match self.entropy_threshold {
            Some(threshold) => shannon_entropy(matched) >= threshold,
            None => true,
        }
    }
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for ch in s.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
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

fn find_detectors_config() -> std::path::PathBuf {
    std::env::var("KEYWATCH_CONFIG_PATH")
        .map(std::path::PathBuf::from)
        .ok()
        .filter(|p| p.exists())
        .or_else(|| {
            let p = std::path::PathBuf::from("detectors.toml");
            if p.exists() { Some(p) } else { None }
        })
        .or_else(|| {
            dirs::config_dir()
                .map(|p| p.join("keywatch").join("detectors.toml"))
                .filter(|p| p.exists())
        })
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("detectors.toml")))
                .filter(|p| p.exists())
        })
        .unwrap_or_else(|| std::path::PathBuf::from("detectors.toml"))
}

pub fn initialize_detectors() -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    let config_path = find_detectors_config();
    let toml_contents = fs::read_to_string(&config_path)
        .map_err(|err| format!("Failed to read {}: {}", config_path.display(), err))?;

    let config: DetectorsConfig = toml::from_str(&toml_contents)
        .map_err(|err| format!("Failed to parse detectors.toml: {}", err))?;

    Ok(config
        .detectors
        .into_iter()
        .map(|det| {
            let allowlist = det.allowlist.as_deref().unwrap_or_default();
            let keywords = det.keywords.as_deref().unwrap_or_default();
            Detector::new(
                &det.name,
                &det.pattern,
                &det.finding_type,
                &det.severity,
                allowlist,
                keywords,
                det.entropy,
            )
        })
        .collect::<Result<Vec<_>, _>>()?)
}
