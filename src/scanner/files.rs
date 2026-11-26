//! Filesystem scan support: exclude-pattern compilation and matching, the
//! baseline self-exclusion, default lockfile excludes, and directory
//! collection.

use crate::cli::ScanArgs;
use crate::config::KeywatchConfig;
use crate::scanner::ScannerError;
use glob::Pattern;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn compile_exclude_patterns(
    args: &ScanArgs,
    config: Option<&KeywatchConfig>,
) -> Result<Vec<Pattern>, ScannerError> {
    let mut exclude_patterns: Vec<Pattern> = Vec::new();

    for pattern in args
        .exclude
        .iter()
        .flat_map(|patterns| patterns.split(','))
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
    {
        exclude_patterns.push(Pattern::new(pattern).map_err(|source| {
            ScannerError::InvalidExcludePattern {
                pattern: pattern.to_string(),
                source,
            }
        })?);
    }

    if let Some(excludes) = config.and_then(|cfg| cfg.exclude.as_ref()) {
        for pattern_str in excludes {
            exclude_patterns.push(Pattern::new(pattern_str).map_err(|source| {
                ScannerError::InvalidConfigExcludePattern {
                    pattern: pattern_str.to_string(),
                    source,
                }
            })?);
        }
    }

    Ok(exclude_patterns)
}

/// Canonical path of the baseline file, so scans never read it. It stores
/// finding hashes that themselves trip detectors, and each
/// `--update-baseline` would re-ingest them, growing the file every run.
/// Compared canonically because a discovered baseline is absolute while the
/// paths a scan reports may be relative to the process directory.
pub(super) fn baseline_exclusion(args: &ScanArgs) -> Option<PathBuf> {
    let baseline_path = args.baseline.as_ref()?;
    fs::canonicalize(baseline_path).ok()
}

/// Lockfiles are excluded by default to reduce checksum noise.
/// They can contain credentials; users can include them explicitly.
const DEFAULT_EXCLUDED_FILES: [&str; 13] = [
    "bun.lock",
    "bun.lockb",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
    "go.sum",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "packages.lock.json",
    "Pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "yarn.lock",
];

pub(super) fn is_default_excluded_file(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    DEFAULT_EXCLUDED_FILES.contains(&name)
}

pub(super) fn is_baseline_file(path: &str, base_dir: &Path, baseline: Option<&PathBuf>) -> bool {
    let Some(baseline) = baseline else {
        return false;
    };
    // Compare file names before paying for a realpath(2) on every scanned
    // file: only a handful can possibly be the baseline.
    let candidate = Path::new(path);
    if candidate.file_name() != baseline.file_name() {
        return false;
    }
    // Staged and history diffs emit repository-root-relative paths no matter
    // where the process runs, so they must be resolved against that root and
    // not against the current directory.
    let anchored = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base_dir.join(candidate)
    };
    fs::canonicalize(anchored).is_ok_and(|candidate| candidate == *baseline)
}
/// A path queued for scanning, with the scan root it was collected under
/// (explicit operands carry none).
pub(super) struct ScanTarget {
    pub(super) path: String,
    pub(super) root: Option<String>,
}

pub(super) fn collect_files(
    dir_path: &str,
    targets: &mut Vec<ScanTarget>,
    root: &str,
    unlistable_dirs: &mut Vec<String>,
    exclude_patterns: &[Pattern],
    visited_paths: &mut usize,
) -> Result<(), ScannerError> {
    // A directory that cannot be listed hides everything beneath it; record
    // it as unscannable instead of silently reporting a clean scan, so
    // --fail-on-unscannable catches it.
    let mut directories = vec![PathBuf::from(dir_path)];
    let roots = [Some(root.to_string())];
    while let Some(directory) = directories.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                unlistable_dirs.push(directory.display().to_string());
                continue;
            }
        };
        for entry in entries {
            if *visited_paths >= super::limits::MAX_PATHS {
                return Err(ScannerError::ResourceLimit {
                    reason: "Filesystem input count exceeds the scan budget".to_string(),
                });
            }
            *visited_paths += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    unlistable_dirs.push(directory.display().to_string());
                    continue;
                }
            };
            let path = entry.path();
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            let Some(path_str) = path.to_str() else {
                unlistable_dirs.push(path.display().to_string());
                continue;
            };
            if matches_exclude_patterns(path_str, &roots, exclude_patterns) {
                targets.push(ScanTarget {
                    path: path_str.to_string(),
                    root: Some(root.to_string()),
                });
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    unlistable_dirs.push(path_str.to_string());
                    continue;
                }
            };
            if file_type.is_file() {
                targets.push(ScanTarget {
                    path: path_str.to_string(),
                    root: Some(root.to_string()),
                });
            } else if file_type.is_dir() {
                directories.push(path);
            } else {
                unlistable_dirs.push(path_str.to_string());
            }
        }
    }
    Ok(())
}

pub(super) fn path_has_git_dir(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == ".git")
}

pub(super) fn matches_exclude_patterns(
    path: &str,
    scan_roots: &[Option<String>],
    patterns: &[Pattern],
) -> bool {
    // Exclude patterns are written with forward slashes, so paths are matched
    // in that form: on Windows a scanned path is `target\\foo` and would
    // otherwise never match `target/**`. Roots are normalized once per call,
    // not once per pattern per file.
    let forward_slashed = path.replace('\\', "/");
    let path = Path::new(forward_slashed.as_str());
    let roots: Vec<String> = scan_roots
        .iter()
        .flatten()
        .map(|root| root.replace('\\', "/"))
        .collect();

    patterns.iter().any(|pattern| {
        pattern.matches_path(path)
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| pattern.matches(name))
            || roots.iter().any(|root| {
                path.strip_prefix(root)
                    .is_ok_and(|relative| pattern.matches_path(relative))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_excluded_lockfiles_match_by_basename() {
        assert!(is_default_excluded_file("Cargo.lock"));
        assert!(is_default_excluded_file("nested/deep/package-lock.json"));
        assert!(is_default_excluded_file("vendor\\yarn.lock"));
        assert!(!is_default_excluded_file("src/Cargo.toml"));
        assert!(!is_default_excluded_file("mylock"));
    }
}
