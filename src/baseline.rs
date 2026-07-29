use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::report::Finding;

fn hash_content(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let domain_separator = "keywatch-baseline-v1";
    let mut hasher = Sha256::new();
    hasher.update(domain_separator.as_bytes());
    hasher.update(content.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BaselineEntry {
    pub file_path: String,
    pub line_number: usize,
    pub finding_type: String,
    pub matched_content_hash: String,
    pub plugin_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Baseline {
    pub version: String,
    pub entries: Vec<BaselineEntry>,
}

impl Baseline {
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            entries: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let contents = fs::read_to_string(path)
            .map_err(|err| format!("Failed to read baseline '{}': {}", path.display(), err))?;

        if contents.trim().is_empty() {
            return Ok(Self::new());
        }

        let baseline: Baseline = serde_json::from_str(&contents)
            .map_err(|err| format!("Failed to parse baseline '{}': {}", path.display(), err))?;

        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|err| format!("Failed to serialize baseline: {}", err))?;

        fs::write(path, json)
            .map_err(|err| format!("Failed to write baseline '{}': {}", path.display(), err))?;

        Ok(())
    }

    fn build_fingerprints(&self) -> HashSet<String> {
        self.entries.iter().map(fingerprint).collect()
    }

    pub fn filter_findings(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let fingerprints = self.build_fingerprints();
        findings
            .into_iter()
            .filter(|f| !fingerprints.contains(&finding_fingerprint(f)))
            .collect()
    }

    pub fn from_findings(findings: &[Finding]) -> Self {
        let entries = findings
            .iter()
            .map(|f| BaselineEntry {
                file_path: f.file_path.clone(),
                line_number: f.line_number,
                finding_type: f.finding_type.clone(),
                matched_content_hash: hash_content(&f.matched_content),
                plugin_name: f.plugin_name.clone(),
            })
            .collect();

        Self {
            version: "1.0".to_string(),
            entries,
        }
    }

    pub fn update_with_findings(&mut self, findings: &[Finding]) {
        let existing: HashSet<String> = self.entries.iter().map(fingerprint).collect();
        for f in findings {
            let fp = finding_fingerprint(f);
            if !existing.contains(&fp) {
                self.entries.push(BaselineEntry {
                    file_path: f.file_path.clone(),
                    line_number: f.line_number,
                    finding_type: f.finding_type.clone(),
                    matched_content_hash: hash_content(&f.matched_content),
                    plugin_name: f.plugin_name.clone(),
                });
            }
        }
    }
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new()
    }
}

fn fingerprint(entry: &BaselineEntry) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        entry.file_path,
        entry.line_number,
        entry.finding_type,
        entry.matched_content_hash,
        entry.plugin_name
    )
}

fn finding_fingerprint(finding: &Finding) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        finding.file_path,
        finding.line_number,
        finding.finding_type,
        hash_content(&finding.matched_content),
        finding.plugin_name
    )
}
