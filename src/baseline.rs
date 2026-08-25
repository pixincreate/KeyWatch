use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

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

#[derive(Debug)]
#[non_exhaustive]
pub enum BaselineError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Serialize {
        source: serde_json::Error,
    },
    Write {
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for BaselineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "Failed to read baseline '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::Parse { path, source } => {
                write!(
                    formatter,
                    "Failed to parse baseline '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::Serialize { source } => {
                write!(formatter, "Failed to serialize baseline: {}", source)
            }
            Self::Write { path, source } => {
                write!(
                    formatter,
                    "Failed to write baseline '{}': {}",
                    path.display(),
                    source
                )
            }
        }
    }
}

impl Error for BaselineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Serialize { source } => Some(source),
            Self::Write { source, .. } => Some(source),
        }
    }
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

        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), BaselineError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|source| BaselineError::Serialize { source })?;

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
}
