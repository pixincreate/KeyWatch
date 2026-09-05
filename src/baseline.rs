use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

use crate::report::Finding;

/// Version of the baseline file format, not of the application itself.
///
/// Bump this only when the on-disk format changes incompatibly
/// (e.g. a different hashing scheme or a new required field).
/// Application releases do not invalidate existing baselines.
const BASELINE_VERSION: &str = "1.0";

/// Conventional baseline filename, discovered automatically (like config)
/// when `--baseline` is not passed explicitly.
pub const DEFAULT_BASELINE_NAME: &str = ".keywatch-baseline.json";

/// Walks up from the first scan path (or the current directory) looking for
/// [`DEFAULT_BASELINE_NAME`], bounded at the repository root or home
/// directory. Returns `None` when no baseline file exists in the tree.
pub fn discover_baseline_path(scan_paths: &[String]) -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    crate::config::find_file_upwards(scan_paths, &cwd, &[DEFAULT_BASELINE_NAME])
}

/// Domain-separation prefix for fingerprint hashes so that baseline hashes
/// cannot collide with plain SHA-256 of the matched content.
const HASH_DOMAIN_SEPARATOR: &str = "keywatch-baseline-v1";

fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN_SEPARATOR.as_bytes());
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BaselineFingerprint {
    file_path: String,
    finding_type: String,
    matched_content_hash: String,
    plugin_name: String,
}

/// Normalizes a path into the form stored in fingerprints: forward slashes
/// and no leading `./`.
///
/// The same finding reaches the baseline spelled several ways — `scan .`
/// yields `./nested/file` (`.\nested\file` on Windows), an explicit path
/// yields what the user typed, and the staged diff always yields
/// forward-slashed repo-relative paths. Folding them together is what lets
/// one committed baseline serve every scan mode, and lets a baseline
/// generated on one platform work on another.
fn normalize_fingerprint_path(path: &str) -> String {
    let separators_folded = path.replace('\\', "/");
    let mut normalized = separators_folded.as_str();
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped;
    }
    normalized.to_string()
}

impl BaselineFingerprint {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            file_path: normalize_fingerprint_path(&finding.file_path),
            finding_type: finding.finding_type.clone(),
            matched_content_hash: hash_content(&finding.matched_content),
            plugin_name: finding.plugin_name.clone(),
        }
    }
}

impl From<&BaselineEntry> for BaselineFingerprint {
    fn from(entry: &BaselineEntry) -> Self {
        Self {
            file_path: normalize_fingerprint_path(&entry.file_path),
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

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BaselineError {
    #[error("Failed to read baseline '{}': {source}", path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("Failed to parse baseline '{}': {source}", path.display())]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error(
        "Baseline '{path}' has unsupported format version '{found}' (expected '{expected}'): it may have been written by an incompatible release"
    )]
    UnsupportedVersion {
        path: PathBuf,
        found: String,
        expected: String,
    },
    #[error("Failed to serialize baseline: {source}")]
    Serialize { source: serde_json::Error },
    #[error("Failed to write baseline '{}': {source}", path.display())]
    Write { path: PathBuf, source: io::Error },
}

impl Baseline {
    pub fn new() -> Self {
        Self {
            version: BASELINE_VERSION.to_string(),
            entries: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, BaselineError> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let contents = fs::read_to_string(path).map_err(|source| BaselineError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        if contents.trim().is_empty() {
            return Ok(Self::new());
        }

        let baseline: Baseline =
            serde_json::from_str(&contents).map_err(|source| BaselineError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

        if baseline.version != BASELINE_VERSION {
            return Err(BaselineError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: baseline.version,
                expected: BASELINE_VERSION.to_string(),
            });
        }

        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), BaselineError> {
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|source| BaselineError::Serialize { source })?;
        json.push('\n');

        fs::write(path, json).map_err(|source| BaselineError::Write {
            path: path.to_path_buf(),
            source,
        })?;

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
        // First occurrence wins within one scan, matching `from_findings`.
        // Pre-existing entries refresh their recorded line number — code
        // edits move findings around — while entries added by this call keep
        // the line they were first seen at.
        let mut index: HashMap<BaselineFingerprint, usize> = self
            .entries
            .iter()
            .enumerate()
            .map(|(entry_index, entry)| (BaselineFingerprint::from(entry), entry_index))
            .collect();
        let mut seen: HashSet<BaselineFingerprint> = HashSet::new();
        for finding in findings {
            let fingerprint = BaselineFingerprint::from_finding(finding);
            if !seen.insert(fingerprint.clone()) {
                continue;
            }
            match index.get(&fingerprint) {
                Some(&entry_index) => self.entries[entry_index].line_number = finding.line_number,
                None => {
                    index.insert(fingerprint, self.entries.len());
                    self.entries.push(Self::entry_from_finding(finding));
                }
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
    use super::{Baseline, hash_content, normalize_fingerprint_path};
    use crate::report::Finding;

    #[test]
    fn hash_content_uses_expected_lowercase_hex() {
        assert_eq!(
            hash_content(""),
            "49969dbf750f1c12188f4646dc9b5ff608ceb35d74e5de79fad99e88ebd445d6"
        );
    }

    #[test]
    fn normalize_fingerprint_path_folds_platform_spellings() {
        // Windows path forms must fold to the same key as the staged diff's
        // forward-slashed, repo-relative paths, or a baseline generated by
        // `scan .` suppresses nothing on Windows.
        for spelling in [
            "nested/config.txt",
            "./nested/config.txt",
            ".\\nested\\config.txt",
            "nested\\config.txt",
        ] {
            assert_eq!(
                normalize_fingerprint_path(spelling),
                "nested/config.txt",
                "unexpected normalization of {spelling:?}"
            );
        }
    }

    #[test]
    fn baseline_matches_findings_across_path_spellings() {
        let recorded = Finding {
            file_path: ".\\secrets.txt".to_string(),
            line_number: 1,
            finding_type: "AWS".to_string(),
            severity: crate::report::Severity::High,
            matched_content: "AKIAIOSFODNN7EXAMPLE".to_string(),
            plugin_name: "AWSKeyDetector".to_string(),
        };
        let baseline = Baseline::from_findings(&[recorded]);

        let seen_again = Finding {
            file_path: "secrets.txt".to_string(),
            line_number: 9,
            finding_type: "AWS".to_string(),
            severity: crate::report::Severity::High,
            matched_content: "AKIAIOSFODNN7EXAMPLE".to_string(),
            plugin_name: "AWSKeyDetector".to_string(),
        };

        assert!(
            baseline.filter_findings(vec![seen_again]).is_empty(),
            "a baseline entry must suppress the same finding under any path spelling"
        );
    }

    #[test]
    fn update_with_findings_refreshes_line_numbers_of_known_entries() {
        let mut baseline = Baseline::from_findings(&[Finding {
            file_path: "secrets.txt".to_string(),
            line_number: 7,
            finding_type: "AWS".to_string(),
            severity: crate::report::Severity::High,
            matched_content: "AKIAIOSFODNN7EXAMPLE".to_string(),
            plugin_name: "AWSKeyDetector".to_string(),
        }]);

        // The secret moved down after an edit; the update must move the
        // recorded line with it instead of adding a duplicate entry.
        baseline.update_with_findings(&[Finding {
            file_path: "secrets.txt".to_string(),
            line_number: 42,
            finding_type: "AWS".to_string(),
            severity: crate::report::Severity::High,
            matched_content: "AKIAIOSFODNN7EXAMPLE".to_string(),
            plugin_name: "AWSKeyDetector".to_string(),
        }]);

        assert_eq!(baseline.entries.len(), 1, "no duplicate entry");
        assert_eq!(baseline.entries[0].line_number, 42);
    }

    #[test]
    fn load_rejects_unknown_format_versions() {
        let dir =
            std::env::temp_dir().join(format!("keywatch_baseline_version_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("baseline.json");
        std::fs::write(&path, r#"{"version":"9.9","entries":[]}"#).expect("write baseline");

        let error = Baseline::load(&path).expect_err("unknown version must fail");
        assert!(
            error
                .to_string()
                .contains("unsupported format version '9.9'"),
            "unexpected error: {error}"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }

    #[test]
    fn save_writes_a_trailing_newline() {
        let dir =
            std::env::temp_dir().join(format!("keywatch_baseline_newline_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("baseline.json");

        Baseline::new().save(&path).expect("save baseline");

        let contents = std::fs::read_to_string(&path).expect("read baseline");
        assert!(contents.ends_with('\n'), "baseline must end with a newline");

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }
}
