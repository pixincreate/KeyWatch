use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt::Write as _, fs, path::Path};

use crate::report::Finding;

/// Version of the baseline file format, not of the application itself.
///
/// Bump this only when the on-disk format changes incompatibly
/// (e.g. a different hashing scheme or a new required field).
/// Application releases do not invalidate existing baselines.
const BASELINE_VERSION: &str = "1.0";

/// Domain-separation prefix for fingerprint hashes so that baseline hashes
/// cannot collide with plain SHA-256 of the matched content.
const HASH_DOMAIN_SEPARATOR: &str = "keywatch-baseline-v1";

fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN_SEPARATOR.as_bytes());
    hasher.update(content.as_bytes());
    let mut output = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut output, "{:02x}", byte);
    }
    output
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BaselineFingerprint {
    file_path: String,
    finding_type: String,
    matched_content_hash: String,
    plugin_name: String,
}

impl BaselineFingerprint {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            file_path: finding.file_path.clone(),
            finding_type: finding.finding_type.clone(),
            matched_content_hash: hash_content(&finding.matched_content),
            plugin_name: finding.plugin_name.clone(),
        }
    }
}

impl From<&BaselineEntry> for BaselineFingerprint {
    fn from(entry: &BaselineEntry) -> Self {
        Self {
            file_path: entry.file_path.clone(),
            finding_type: entry.finding_type.clone(),
            matched_content_hash: entry.matched_content_hash.clone(),
            plugin_name: entry.plugin_name.clone(),
        }
    }
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
            version: BASELINE_VERSION.to_string(),
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

    fn build_fingerprints(&self) -> HashSet<BaselineFingerprint> {
        self.entries.iter().map(BaselineFingerprint::from).collect()
    }

    fn entry_from_finding(finding: &Finding) -> BaselineEntry {
        BaselineEntry {
            file_path: finding.file_path.clone(),
            line_number: finding.line_number,
            finding_type: finding.finding_type.clone(),
            matched_content_hash: hash_content(&finding.matched_content),
            plugin_name: finding.plugin_name.clone(),
        }
    }

    pub fn filter_findings(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let fingerprints = self.build_fingerprints();
        findings
            .into_iter()
            .filter(|finding| !fingerprints.contains(&BaselineFingerprint::from_finding(finding)))
            .collect()
    }

    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut entries = Vec::new();
        let mut fingerprints = HashSet::new();

        for finding in findings {
            let fingerprint = BaselineFingerprint::from_finding(finding);
            if fingerprints.insert(fingerprint) {
                entries.push(Self::entry_from_finding(finding));
            }
        }

        Self {
            version: BASELINE_VERSION.to_string(),
            entries,
        }
    }

    pub fn update_with_findings(&mut self, findings: &[Finding]) {
        let mut existing: HashSet<BaselineFingerprint> =
            self.entries.iter().map(BaselineFingerprint::from).collect();
        for f in findings {
            let fingerprint = BaselineFingerprint::from_finding(f);
            if existing.insert(fingerprint) {
                self.entries.push(Self::entry_from_finding(f));
            }
        }
    }
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::hash_content;

    #[test]
    fn hash_content_uses_expected_lowercase_hex() {
        assert_eq!(
            hash_content(""),
            "49969dbf750f1c12188f4646dc9b5ff608ceb35d74e5de79fad99e88ebd445d6"
        );
    }
}
