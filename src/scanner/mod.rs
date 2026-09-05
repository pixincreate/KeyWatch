//! Scan orchestration: resolves detectors, dispatches to the mode-specific
//! scanners (stream, files, staged diff, git history), and aggregates the
//! report metadata.

use crate::cli::ScanArgs;
use crate::config::KeywatchConfig;
use crate::detector::{initialize_detectors, initialize_trusted_detectors, untrusted_root};
use crate::report::{Finding, ScanMetadata};
use rayon::prelude::*;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

mod error;
mod files;
mod lines;
mod staged;

pub use error::ScannerError;

use files::{
    baseline_exclusion, collect_files, compile_exclude_patterns, is_baseline_file,
    is_default_excluded_file, matches_exclude_patterns, path_has_git_dir,
};
use lines::{LineScanContext, scan_file_stream, scan_stream};
use staged::{StagedScan, scan_git_output, scan_staged_diff, scan_undiffable_blobs};
/// Git config that must be overridden for every diff-based scan: the parser
/// depends on undecorated `diff --git`/`@@`/`+` framing and literal `a/`/`b/`
/// path prefixes, so user git config that colors, re-prefixes, quotes, or
/// glob-expands would otherwise hide added lines or mangle path attribution.
/// One list for both `--staged` and `--git-history`: a new override added to
/// only one mode leaves the other silently vulnerable.
const GIT_DIFF_FRAMING_ARGS: &[&str] = &[
    "--literal-pathspecs",
    "-c",
    "diff.external=",
    "-c",
    "color.ui=false",
    "-c",
    "diff.mnemonicPrefix=false",
    "-c",
    "diff.noprefix=false",
    "-c",
    "core.quotePath=false",
    "-c",
    "diff.relative=false",
];

pub fn run_scan(
    args: &ScanArgs,
    config: Option<&KeywatchConfig>,
) -> Result<(Vec<Finding>, ScanMetadata), ScannerError> {
    let mut detectors = if args.no_config_discovery {
        initialize_trusted_detectors(&untrusted_roots(args))
    } else {
        initialize_detectors()
    }
    .map_err(|source| ScannerError::DetectorInit { source })?;

    if let Some(cfg) = config {
        cfg.apply_to(&mut detectors)
            .map_err(|source| ScannerError::Config { source })?;
    }
    // A pattern carrying the dot-matches-newline flag anywhere — `(?s)` or
    // the grouped `(?s:...)` form — spans lines and must run per-chunk, not
    // per-line, or multiline secrets slip past it.
    let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
        .iter()
        .partition(|detector| detector.is_multiline());

    // Resolved once: every scan mode must skip the baseline file itself.
    let excluded_baseline = baseline_exclusion(args);

    if args.git_history {
        let git_root = args
            .paths
            .first()
            .map(Path::new)
            .unwrap_or_else(|| Path::new("."));
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        // History diffs are repository-root-relative; the same root anchors
        // baseline self-exclusion.
        let repo_root = git_repo_root(&cwd.join(git_root)).unwrap_or_else(|| cwd.join(git_root));
        let mut command = std::process::Command::new("git");
        command
            .current_dir(git_root)
            .args(GIT_DIFF_FRAMING_ARGS)
            .args([
                "log",
                "-p",
                "-U0",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
            ]);

        // `git log -p` emits the same diff framing as `git diff --cached`, so
        // history reuses the staged parser. That gives it real file paths
        // instead of a synthetic "<git-history>" key — which no baseline
        // entry could ever match — plus --exclude and baseline-file
        // exclusion, none of which this mode previously applied.
        let exclude_patterns = compile_exclude_patterns(args, config)?;
        let history = scan_git_output(
            command,
            ScannerError::GitLogNonZero,
            |reader| {
                scan_staged_diff(
                    reader,
                    &exclude_patterns,
                    excluded_baseline.as_ref(),
                    &repo_root,
                    &multiline_detectors,
                    &line_detectors,
                )
            },
            |source| ScannerError::RunGitLog { source },
        )?;

        let mut metadata = history.metadata;
        // Blobs are only re-readable from the index, not from history, so a
        // git-rendered binary in history is unscannable rather than excluded.
        metadata.unscannable_files = history.undiffable_files;

        let mut findings = history.findings;
        sort_findings(&mut findings);
        return Ok((findings, metadata));
    }

    if args.staged {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let repo_root = git_repo_root(&cwd).unwrap_or(cwd);
        let exclude_patterns = compile_exclude_patterns(args, config)?;
        let mut command = std::process::Command::new("git");
        command.args(GIT_DIFF_FRAMING_ARGS).args([
            "diff",
            "--cached",
            "-U0",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--",
        ]);
        command.args(&args.paths);

        let staged = scan_git_output(
            command,
            ScannerError::GitDiffNonZero,
            |reader| {
                scan_staged_diff(
                    reader,
                    &exclude_patterns,
                    excluded_baseline.as_ref(),
                    &repo_root,
                    &multiline_detectors,
                    &line_detectors,
                )
            },
            |source| ScannerError::RunGitDiff { source },
        )?;

        let StagedScan {
            mut findings,
            mut metadata,
            undiffable_files,
        } = staged;

        let (blob_findings, blob_lines, skipped) =
            scan_undiffable_blobs(&undiffable_files, &multiline_detectors, &line_detectors)?;
        findings.extend(blob_findings);
        metadata.total_lines += blob_lines;
        metadata.files_scanned += undiffable_files.len() - skipped.len();
        metadata.unscannable_files.extend(skipped);

        sort_findings(&mut findings);

        return Ok((findings, metadata));
    }

    if args.stdin {
        let stdin = std::io::stdin();
        let reader = BufReader::new(stdin);
        let (findings, total_lines) =
            scan_stream(reader, "<stdin>", &multiline_detectors, &line_detectors)?;

        let metadata = ScanMetadata {
            files_scanned: 1,
            total_lines,
            excluded_files: Vec::new(),
            unscannable_files: Vec::new(),
            suppressed_by_baseline: 0,
        };

        return Ok((findings, metadata));
    }

    let mut target_paths = Vec::new();

    for path_str in &args.paths {
        let path = Path::new(path_str);
        let Ok(metadata) = fs::symlink_metadata(path) else {
            continue;
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_file() {
            target_paths.push((path_str.clone(), None));
        } else if file_type.is_dir() {
            collect_files(path_str, &mut target_paths, path_str);
        }
    }

    target_paths.sort_by(|a, b| a.0.cmp(&b.0));

    let mut unique_paths: std::collections::BTreeMap<String, Vec<Option<String>>> =
        std::collections::BTreeMap::new();
    for (path, root) in target_paths {
        let roots = unique_paths.entry(path).or_default();
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    let unique_paths: Vec<_> = unique_paths.into_iter().collect();

    let exclude_patterns = compile_exclude_patterns(args, config)?;
    let line_scan_context = LineScanContext::new(&line_detectors);
    let scan_base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    /// One scanned path's contribution to the report.
    struct FileOutcome {
        findings: Vec<Finding>,
        lines_seen: usize,
        scanned: bool,
        excluded: Option<String>,
        unscannable: Option<String>,
    }

    impl FileOutcome {
        fn skipped_but_reported(path: String) -> Self {
            Self {
                findings: Vec::new(),
                lines_seen: 0,
                scanned: false,
                excluded: Some(path),
                unscannable: None,
            }
        }

        fn ignored() -> Self {
            Self {
                findings: Vec::new(),
                lines_seen: 0,
                scanned: false,
                excluded: None,
                unscannable: None,
            }
        }
    }

    let results: Vec<FileOutcome> = unique_paths
        .into_par_iter()
        .map(|(path, roots)| {
            if path_has_git_dir(Path::new(&path)) {
                return FileOutcome::skipped_but_reported(path);
            }

            if matches_exclude_patterns(&path, &roots, &exclude_patterns)
                || is_baseline_file(&path, &scan_base_dir, excluded_baseline.as_ref())
                || is_default_excluded_file(&path)
            {
                return FileOutcome::skipped_but_reported(path);
            }

            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => return FileOutcome::ignored(),
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !file_type.is_file() {
                return FileOutcome::ignored();
            }

            // Streamed: memory stays bounded for huge files, invalid UTF-8
            // decodes lossily instead of skipping the file, and a NUL byte
            // marks the file binary (reported as unscannable).
            let mut reader = match fs::File::open(&path) {
                Ok(file) => BufReader::new(file),
                Err(_) => return FileOutcome::ignored(),
            };
            let scanned = match scan_file_stream(
                &mut reader,
                &path,
                &multiline_detectors,
                &line_scan_context,
            ) {
                Ok(scanned) => scanned,
                Err(_) => return FileOutcome::ignored(),
            };
            if scanned.binary {
                return FileOutcome {
                    findings: Vec::new(),
                    lines_seen: 0,
                    scanned: false,
                    excluded: None,
                    unscannable: Some(path),
                };
            }

            FileOutcome {
                findings: scanned.findings,
                lines_seen: scanned.total_lines,
                scanned: true,
                excluded: None,
                unscannable: None,
            }
        })
        .collect();

    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let mut total_lines = 0;
    let mut excluded_files = Vec::new();
    let mut unscannable_files = Vec::new();

    for outcome in results {
        findings.extend(outcome.findings);
        if outcome.scanned {
            files_scanned += 1;
            total_lines += outcome.lines_seen;
        }
        if let Some(e) = outcome.excluded {
            excluded_files.push(e);
        }
        if let Some(u) = outcome.unscannable {
            unscannable_files.push(u);
        }
    }

    sort_findings(&mut findings);

    let metadata = ScanMetadata {
        files_scanned,
        total_lines,
        excluded_files,
        unscannable_files,
        suppressed_by_baseline: 0,
    };

    Ok((findings, metadata))
}

/// Directories the scanned tree's owner may control, handed to trusted
/// detector initialisation so a repository cannot supply its own detector set
/// through `KEYWATCH_CONFIG_PATH`. Git-backed modes scan a whole working
/// tree, so that tree's root is untrusted; file scans distrust everything at
/// or below each target's enclosing repository root. The current directory is
/// always included: a repository can reach the environment through
fn untrusted_roots(args: &ScanArgs) -> Vec<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut roots = vec![cwd.clone()];

    if args.staged {
        if let Some(root) = git_repo_root(&cwd) {
            roots.push(root);
        }
    } else if args.git_history {
        let git_root = cwd.join(args.paths.first().map(String::as_str).unwrap_or("."));
        if let Some(root) = git_repo_root(&git_root) {
            roots.push(root);
        }
    } else {
        for path in &args.paths {
            roots.push(untrusted_root(path, &cwd));
        }
    }

    roots
}

/// The enclosing repository's root, via `git rev-parse --show-toplevel`.
/// `None` when the directory is not inside a working tree.
fn git_repo_root(dir: &Path) -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!root.is_empty()).then(|| PathBuf::from(root))
}

/// Orders findings by path then line, the stable shape every mode reports.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line_number.cmp(&b.line_number))
    });
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::detector::Detector;

    pub(crate) fn make_test_detector(
        name: &str,
        pattern: &str,
        finding_type: &str,
        severity: &str,
    ) -> Detector {
        Detector::new(name, pattern, finding_type, severity, &[], &[], None).unwrap()
    }
}
