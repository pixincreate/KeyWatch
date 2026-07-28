use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::report::Finding;

/// A single entry in the baseline file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BaselineEntry {
    pub file_path: String,
    pub line_number: usize,
    pub finding_type: String,
    pub matched_content: String,
    pub plugin_name: String,
}

/// The baseline file structure.
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

    /// Load a baseline from a file path. Returns an empty baseline if the file doesn't exist.
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

    /// Save the baseline to a file path.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|err| format!("Failed to serialize baseline: {}", err))?;

        fs::write(path, json)
            .map_err(|err| format!("Failed to write baseline '{}': {}", path.display(), err))?;

        Ok(())
    }

    /// Build a HashSet of fingerprints for O(1) lookup.
    fn build_fingerprints(&self) -> HashSet<String> {
        self.entries.iter().map(|e| fingerprint(e)).collect()
    }

    /// Filter findings, removing those already in the baseline.
    pub fn filter_findings(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let fingerprints = self.build_fingerprints();
        findings
            .into_iter()
            .filter(|f| !fingerprints.contains(&finding_fingerprint(f)))
            .collect()
    }

    /// Create a new baseline from a list of findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let entries = findings
            .iter()
            .map(|f| BaselineEntry {
                file_path: f.file_path.clone(),
                line_number: f.line_number,
                finding_type: f.finding_type.clone(),
                matched_content: f.matched_content.clone(),
                plugin_name: f.plugin_name.clone(),
            })
            .collect();

        Self {
            version: "1.0".to_string(),
            entries,
        }
    }
}

/// Create a fingerprint string for a baseline entry.
fn fingerprint(entry: &BaselineEntry) -> String {
    format!(
        "{}:{}:{}:{}",
        entry.file_path, entry.line_number, entry.finding_type, entry.plugin_name
    )
}

/// Create a fingerprint string for a finding.
fn finding_fingerprint(finding: &Finding) -> String {
    format!(
        "{}:{}:{}:{}",
        finding.file_path, finding.line_number, finding.finding_type, finding.plugin_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(file: &str, line: usize, ftype: &str, content: &str, plugin: &str) -> Finding {
        Finding {
            file_path: file.to_string(),
            line_number: line,
            finding_type: ftype.to_string(),
            severity: crate::report::Severity::High,
            matched_content: content.to_string(),
            plugin_name: plugin.to_string(),
        }
    }

    #[test]
    fn test_baseline_filters_known_findings() {
        let baseline = Baseline {
            version: "1.0".to_string(),
            entries: vec![
                BaselineEntry {
                    file_path: "test.txt".to_string(),
                    line_number: 5,
                    finding_type: "AWS Key".to_string(),
                    matched_content: "AKIA...".to_string(),
                    plugin_name: "AWSAccessKeyDetector".to_string(),
                },
            ],
        };

        let findings = vec![
            make_finding("test.txt", 5, "AWS Key", "AKIAIOSFODNN7EXAMPLE", "AWSAccessKeyDetector"),
            make_finding("other.txt", 1, "API Key", "sk-abc", "GenericKeyValueDetector"),
        ];

        let filtered = baseline.filter_findings(findings);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].file_path, "other.txt");
    }

    #[test]
    fn test_baseline_allows_new_findings() {
        let baseline = Baseline::new();
        let findings = vec![make_finding("test.txt", 1, "API Key", "sk-abc", "GenericKeyValueDetector")];
        let filtered = baseline.filter_findings(findings);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_baseline_save_and_load() {
        let temp_file = std::env::temp_dir().join("keywatch_test_baseline.json");
        let baseline = Baseline {
            version: "1.0".to_string(),
            entries: vec![BaselineEntry {
                file_path: "a.txt".to_string(),
                line_number: 1,
                finding_type: "X".to_string(),
                matched_content: "secret".to_string(),
                plugin_name: "D".to_string(),
            }],
        };

        baseline.save(&temp_file).unwrap();
        let loaded = Baseline::load(&temp_file).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].file_path, "a.txt");

        let _ = fs::remove_file(&temp_file);
    }

    #[test]
    fn test_baseline_from_findings() {
        let findings = vec![
            make_finding("f1.txt", 1, "A", "x", "D1"),
            make_finding("f2.txt", 2, "B", "y", "D2"),
        ];
        let baseline = Baseline::from_findings(&findings);
        assert_eq!(baseline.entries.len(), 2);
    }
}
