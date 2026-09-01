use crate::cli::ScanArgs;
use crate::config::KeywatchConfig;
use crate::detector::{Detector, initialize_detectors, initialize_trusted_detectors, untrusted_root};
use crate::report::{Finding, ScanMetadata};
use aho_corasick::AhoCorasick;
use glob::Pattern;
use rayon::prelude::*;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

mod error;

pub use error::ScannerError;

const INLINE_SUPPRESS: &str = "keywatch:ignore";

fn is_inline_suppressed(line: &str) -> bool {
    line.to_lowercase().contains(INLINE_SUPPRESS)
}

/// Lowercases `src` into `buf` without allocating a fresh string per line.
fn to_lowercase_into(src: &str, buf: &mut String) {
    buf.clear();
    buf.extend(src.chars().flat_map(char::to_lowercase));
}

/// Folds every distinct detector keyword into one Aho-Corasick automaton so a
/// line is checked against all keywords in a single pass instead of one
/// substring search per keyword per detector.
struct KeywordPrefilter {
    automaton: Option<AhoCorasick>,
    /// Automaton pattern index -> indices of detectors owning that keyword.
    owners: Vec<Vec<usize>>,
    /// Detectors without keywords always run their regex.
    unconditional: Vec<usize>,
    detector_count: usize,
}

impl KeywordPrefilter {
    fn new(line_detectors: &[&Detector]) -> Self {
        let mut patterns: Vec<&str> = Vec::new();
        let mut pattern_indices: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        let mut owners: Vec<Vec<usize>> = Vec::new();
        let mut unconditional = Vec::new();

        for (detector_index, detector) in line_detectors.iter().enumerate() {
            if detector.keywords.is_empty() {
                unconditional.push(detector_index);
                continue;
            }
            for keyword in &detector.keywords {
                let pattern_index = *pattern_indices.entry(keyword.as_str()).or_insert_with(|| {
                    patterns.push(keyword.as_str());
                    owners.push(Vec::new());
                    patterns.len() - 1
                });
                owners[pattern_index].push(detector_index);
            }
        }

        // If the automaton cannot be built, every keyword detector runs
        // unconditionally: slower, but it can never miss a secret.
        let automaton = match AhoCorasick::new(&patterns) {
            Ok(automaton) if !patterns.is_empty() => Some(automaton),
            _ => {
                unconditional = (0..line_detectors.len()).collect();
                None
            }
        };

        Self {
            automaton,
            owners,
            unconditional,
            detector_count: line_detectors.len(),
        }
    }

    /// Marks the detectors whose keywords occur in `lowered_line` in
    /// `candidates`, a scratch buffer reused across lines.
    fn candidates_into(&self, lowered_line: &str, candidates: &mut Vec<bool>) {
        candidates.clear();
        candidates.resize(self.detector_count, false);
        for &detector_index in &self.unconditional {
            candidates[detector_index] = true;
        }
        if let Some(automaton) = &self.automaton {
            for keyword_match in automaton.find_overlapping_iter(lowered_line) {
                for &detector_index in &self.owners[keyword_match.pattern().as_usize()] {
                    candidates[detector_index] = true;
                }
            }
        }
    }
}

struct LineScanContext<'detectors> {
    line_detectors: &'detectors [&'detectors Detector],
    prefilter: KeywordPrefilter,
}

impl<'detectors> LineScanContext<'detectors> {
    fn new(line_detectors: &'detectors [&'detectors Detector]) -> Self {
        Self {
            line_detectors,
            prefilter: KeywordPrefilter::new(line_detectors),
        }
    }
}

/// Per-line scratch buffers, reused across lines to avoid allocating in the
/// hot loop. Each scanning loop owns one (they are not shared across threads).
#[derive(Default)]
struct LineScratch {
    lowered_line: String,
    candidates: Vec<bool>,
}

fn scan_line_detectors(
    line: &str,
    line_number: usize,
    path: &str,
    context: &LineScanContext<'_>,
    scratch: &mut LineScratch,
    findings: &mut Vec<Finding>,
) {
    to_lowercase_into(line, &mut scratch.lowered_line);
    if scratch.lowered_line.contains(INLINE_SUPPRESS) {
        return;
    }

    context
        .prefilter
        .candidates_into(&scratch.lowered_line, &mut scratch.candidates);

    for (detector_index, detector) in context.line_detectors.iter().enumerate() {
        if !scratch.candidates[detector_index] {
            continue;
        }
        for mat in detector.regex.find_iter(line) {
            if detector.accepts_match(mat.as_str()) {
                findings.push(Finding {
                    file_path: path.to_string(),
                    line_number,
                    matched_content: mat.as_str().to_string(),
                    finding_type: detector.finding_type.clone(),
                    severity: detector.severity,
                    plugin_name: detector.name.clone(),
                });
            }
        }
    }
}

fn scan_multiline_chunk(
    chunk: &str,
    line_offset: usize,
    path: &str,
    multiline_detectors: &[&Detector],
    findings: &mut Vec<Finding>,
) {
    if multiline_detectors.is_empty() {
        return;
    }
    let lowered_chunk = chunk.to_lowercase();
    for detector in multiline_detectors {
        if detector.has_keywords(&lowered_chunk) {
            for mat in detector.regex.find_iter(chunk) {
                let line_in_chunk = chunk[..mat.start()].matches('\n').count() + 1;
                let line_content = chunk
                    .lines()
                    .nth(line_in_chunk.saturating_sub(1))
                    .unwrap_or_default();
                let line_is_suppressed = is_inline_suppressed(line_content);

                if !line_is_suppressed && detector.accepts_match(mat.as_str()) {
                    findings.push(Finding {
                        file_path: path.to_string(),
                        line_number: line_offset + line_in_chunk,
                        matched_content: mat.as_str().to_string(),
                        finding_type: detector.finding_type.clone(),
                        severity: detector.severity,
                        plugin_name: detector.name.clone(),
                    });
                }
            }
        }
    }
}

fn scan_content(
    content: &str,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext<'_>,
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut total_lines = 0;

    scan_multiline_chunk(content, 0, path, multiline_detectors, &mut findings);

    let mut scratch = LineScratch::default();
    for (line_idx, line) in content.lines().enumerate() {
        total_lines += 1;
        scan_line_detectors(
            line,
            line_idx + 1,
            path,
            context,
            &mut scratch,
            &mut findings,
        );
    }

    (findings, total_lines)
}

fn scan_stream<ReaderType: BufRead>(
    reader: ReaderType,
    path: &str,
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, usize), ScannerError> {
    const CHUNK_SIZE: usize = 1000;
    const OVERLAP_LINES: usize = 50;

    let context = LineScanContext::new(line_detectors);
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut buffer: Vec<String> = Vec::with_capacity(CHUNK_SIZE + OVERLAP_LINES);
    let mut line_offset = 0;
    let mut scratch = LineScratch::default();

    for line_result in reader.lines() {
        let line = line_result.map_err(|source| ScannerError::ReadStream {
            path: path.to_string(),
            source,
        })?;
        total_lines += 1;

        scan_line_detectors(
            &line,
            total_lines,
            path,
            &context,
            &mut scratch,
            &mut findings,
        );

        buffer.push(line);

        if buffer.len() >= CHUNK_SIZE + OVERLAP_LINES {
            let chunk = buffer.join("\n");
            scan_multiline_chunk(
                &chunk,
                line_offset,
                path,
                multiline_detectors,
                &mut findings,
            );
            line_offset += buffer.len() - OVERLAP_LINES;
            buffer.drain(..buffer.len() - OVERLAP_LINES);
        }
    }

    if !buffer.is_empty() {
        let chunk = buffer.join("\n");
        scan_multiline_chunk(
            &chunk,
            line_offset,
            path,
            multiline_detectors,
            &mut findings,
        );
    }

    Ok((findings, total_lines))
}

/// Runs `command`, feeds its stdout to `scan`, and reaps the child process.
///
/// Both git-backed scan modes share this so the process lifetime is handled
/// in exactly one place: on a scan error the child is killed rather than left
/// writing into a closed pipe, and it is always waited on before the status
/// is checked.
fn scan_git_output<T>(
    mut command: std::process::Command,
    nonzero_status: ScannerError,
    scan: impl FnOnce(BufReader<std::process::ChildStdout>) -> Result<T, ScannerError>,
    spawn_failed: impl FnOnce(std::io::Error) -> ScannerError,
) -> Result<T, ScannerError> {
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(spawn_failed)?;

    let stdout = child.stdout.take().ok_or(ScannerError::CaptureGitStdout)?;
    let scanned = scan(BufReader::new(stdout));
    if scanned.is_err() {
        let _ = child.kill();
    }

    let status = child
        .wait()
        .map_err(|source| ScannerError::GitProcess { source })?;
    let scanned = scanned?;

    status.success().then_some(scanned).ok_or(nonzero_status)
}

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
    let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
        .iter()
        .partition(|detector| detector.regex.as_str().contains("(?s)"));

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
        command.current_dir(git_root).args([
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
        // The parser depends on undecorated `diff --git`/`@@`/`+` framing and
        // literal `a/`/`b/` path prefixes, so user git config that colors,
        // re-prefixes, quotes, or glob-expands must be overridden here — a
        // stray `color.ui = always` would otherwise hide every added line.
        command.args([
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

    let results: Vec<(Vec<Finding>, usize, usize, Option<String>)> = unique_paths
        .into_par_iter()
        .map(|(path, roots)| {
            if path_has_git_dir(Path::new(&path)) {
                return (Vec::new(), 0, 0, Some(path));
            }

            if matches_exclude_patterns(&path, &roots, &exclude_patterns)
                || is_baseline_file(&path, &scan_base_dir, excluded_baseline.as_ref())
                || is_default_excluded_file(&path)
            {
                return (Vec::new(), 0, 0, Some(path));
            }

            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => return (Vec::new(), 0, 0, None),
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !file_type.is_file() {
                return (Vec::new(), 0, 0, None);
            }

            let full_content = match fs::read(&path) {
                Ok(bytes) => {
                    if bytes.contains(&0) {
                        return (Vec::new(), 0, 0, None);
                    }
                    match String::from_utf8(bytes) {
                        Ok(content) => content,
                        Err(_) => return (Vec::new(), 0, 0, None),
                    }
                }
                Err(_) => return (Vec::new(), 0, 0, None),
            };

            let (file_findings, file_lines) = scan_content(
                &full_content,
                &path,
                &multiline_detectors,
                &line_scan_context,
            );

            (file_findings, 1, file_lines, None)
        })
        .collect();

    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let mut total_lines = 0;
    let mut excluded_files = Vec::new();

    for (file_findings, file_count, file_lines, excluded) in results {
        findings.extend(file_findings);
        files_scanned += file_count;
        total_lines += file_lines;
        if let Some(e) = excluded {
            excluded_files.push(e);
        }
    }

    sort_findings(&mut findings);

    let metadata = ScanMetadata {
        files_scanned,
        total_lines,
        excluded_files,
        unscannable_files: Vec::new(),
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
/// `.envrc`/direnv the moment the operator cds into it.
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

fn compile_exclude_patterns(
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
/// scanned path may be relative (`./.keywatch-baseline.json`).
fn baseline_exclusion(args: &ScanArgs) -> Option<PathBuf> {
    let baseline_path = args.baseline.as_ref()?;
    fs::canonicalize(baseline_path).ok()
}

/// Lockfiles hold checksums and resolved URLs, never credentials, and their
/// generated hashes otherwise flood reports and baselines with "Random
/// String" findings. Excluded by basename at any depth in every
/// filesystem-backed mode, matching gitleaks; `--stdin` is unaffected.
const DEFAULT_EXCLUDED_FILES: [&str; 9] = [
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
    "go.sum",
    "package-lock.json",
    "packages.lock.json",
    "Pipfile.lock",
    "poetry.lock",
    "yarn.lock",
];

fn is_default_excluded_file(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    DEFAULT_EXCLUDED_FILES.contains(&name)
}

fn is_baseline_file(path: &str, base_dir: &Path, baseline: Option<&PathBuf>) -> bool {
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

fn parse_hunk_new_start(header: &str) -> usize {
    let parsed = header
        .split_whitespace()
        .find(|token| token.starts_with('+'))
        .and_then(|token| {
            token[1..]
                .split(',')
                .next()
                .and_then(|start| start.parse().ok())
        });
    match parsed {
        Some(start) => start,
        // Scanning with a wrong offset still reports the secret; the message
        // makes the misattribution visible instead of silently writing 0.
        None => {
            eprintln!("keywatch: unrecognized hunk header, line numbers may be off: {header}");
            0
        }
    }
}

/// Undoes git's C-style path quoting. `core.quotePath=false` (pinned on both
/// git invocations) leaves non-ASCII names unquoted, but names containing
/// quotes or control characters are still emitted as `"b/we\"ird.txt"`.
fn c_unquote(quoted: &str) -> String {
    let inner = quoted
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(quoted);
    let mut unescaped: Vec<u8> = Vec::with_capacity(inner.len());
    let mut bytes = inner.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            unescaped.push(byte);
            continue;
        }
        match bytes.next() {
            Some(b'"') => unescaped.push(b'"'),
            Some(b'\\') => unescaped.push(b'\\'),
            Some(b't') => unescaped.push(b'\t'),
            Some(b'n') => unescaped.push(b'\n'),
            Some(b'r') => unescaped.push(b'\r'),
            Some(first @ b'0'..=b'3') => {
                // Git escapes arbitrary bytes as three-digit octal.
                let mut value = u32::from(first - b'0');
                for _ in 0..2 {
                    match bytes.next() {
                        Some(digit @ b'0'..=b'7') => value = value * 8 + u32::from(digit - b'0'),
                        _ => break,
                    }
                }
                unescaped.push(value as u8);
            }
            Some(other) => {
                // Not a recognized escape; keep both characters.
                unescaped.push(b'\\');
                unescaped.push(other);
            }
            None => unescaped.push(b'\\'),
        }
    }
    String::from_utf8_lossy(&unescaped).into_owned()
}

fn parse_diff_target_path(target: &str) -> Option<String> {
    let target = target.trim_end();
    if target == "/dev/null" {
        return None;
    }
    let unquoted = c_unquote(target);
    let target = unquoted.strip_prefix("b/").unwrap_or(&unquoted);
    Some(target.to_string())
}

fn flush_staged_hunk(
    path: Option<&str>,
    hunk_start: usize,
    hunk_added: &mut Vec<String>,
    multiline_detectors: &[&Detector],
    findings: &mut Vec<Finding>,
) {
    if hunk_added.is_empty() {
        return;
    }
    if let Some(path) = path {
        let chunk = hunk_added.join("\n");
        scan_multiline_chunk(
            &chunk,
            hunk_start.saturating_sub(1),
            path,
            multiline_detectors,
            findings,
        );
    }
    hunk_added.clear();
}

/// Best-effort path from a `Binary files a/x and b/x differ` marker: the
/// post-image side, for surfacing skipped files. Sides that git quoted are
/// separated by a quoted-space-quoted delimiter, which also keeps `" and "`
/// inside a quoted name from splitting the pair.
fn parse_binary_marker_path(marker: &str) -> String {
    let Some(paths) = marker.strip_suffix(" differ") else {
        return marker.to_string();
    };
    let target = if paths.contains("\" and \"") {
        paths
            .rsplit("\" and \"")
            .next()
            .map(|tail| format!("\"{tail}"))
    } else {
        paths.rsplit(" and ").next().map(str::to_string)
    };
    match target {
        Some(target) => {
            let unquoted = c_unquote(&target);
            unquoted
                .strip_prefix("b/")
                .unwrap_or(&unquoted)
                .to_string()
        }
        None => marker.to_string(),
    }
}

/// Scans only the added lines of the staged diff, attributing findings to the
/// real file path and post-image line number so `--baseline` entries match.
/// Hunk state is tracked because added content may itself start with "+".
/// Lines are decoded lossily so one non-UTF-8 file cannot abort the scan.
fn scan_staged_diff<ReaderType: BufRead>(
    mut reader: ReaderType,
    exclude_patterns: &[Pattern],
    excluded_baseline: Option<&PathBuf>,
    base_dir: &Path,
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<StagedScan, ScannerError> {
    let context = LineScanContext::new(line_detectors);
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut scanned_files: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut excluded_files: Vec<String> = Vec::new();
    let mut undiffable_files: Vec<String> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut in_hunk = false;
    let mut next_line_number = 0;
    let mut hunk_start = 0;
    let mut hunk_added: Vec<String> = Vec::new();
    let mut scratch = LineScratch::default();
    let mut raw_line: Vec<u8> = Vec::new();

    loop {
        raw_line.clear();
        let bytes_read =
            reader
                .read_until(b'\n', &mut raw_line)
                .map_err(|source| ScannerError::ReadStream {
                    path: "<staged>".to_string(),
                    source,
                })?;
        if bytes_read == 0 {
            break;
        }
        if raw_line.last() == Some(&b'\n') {
            raw_line.pop();
        }
        if raw_line.last() == Some(&b'\r') {
            raw_line.pop();
        }
        let line = String::from_utf8_lossy(&raw_line);

        if in_hunk {
            if let Some(content) = line.strip_prefix('+') {
                let line_number = next_line_number;
                next_line_number += 1;
                let Some(path) = current_path.as_deref() else {
                    continue;
                };
                total_lines += 1;
                scanned_files.insert(path.to_string());
                scan_line_detectors(
                    content,
                    line_number,
                    path,
                    &context,
                    &mut scratch,
                    &mut findings,
                );
                hunk_added.push(content.to_string());
                continue;
            }
            if line.starts_with('-') || line.starts_with('\\') {
                continue;
            }
        }

        if line.starts_with("@@") {
            flush_staged_hunk(
                current_path.as_deref(),
                hunk_start,
                &mut hunk_added,
                multiline_detectors,
                &mut findings,
            );
            hunk_start = parse_hunk_new_start(&line);
            next_line_number = hunk_start;
            in_hunk = true;
            continue;
        }

        if line.starts_with("diff ") {
            flush_staged_hunk(
                current_path.as_deref(),
                hunk_start,
                &mut hunk_added,
                multiline_detectors,
                &mut findings,
            );
            in_hunk = false;
            current_path = None;
            continue;
        }

        if let Some(target) = line.strip_prefix("+++ ") {
            current_path = match parse_diff_target_path(target) {
                Some(path)
                    if matches_exclude_patterns(&path, &[], exclude_patterns)
                        || is_baseline_file(&path, base_dir, excluded_baseline)
                        || is_default_excluded_file(&path) =>
                {
                    excluded_files.push(path);
                    None
                }
                other => other,
            };
            continue;
        }

        // A `-diff` gitattribute (or a true binary) yields no hunks. The diff
        // tells us nothing about the content, so record the path and read the
        // staged blob directly rather than reporting the file as clean.
        if let Some(marker) = line.strip_prefix("Binary files ") {
            let path = parse_binary_marker_path(marker);
            if matches_exclude_patterns(&path, &[], exclude_patterns)
                || is_baseline_file(&path, base_dir, excluded_baseline)
                || is_default_excluded_file(&path)
            {
                excluded_files.push(path);
            } else {
                undiffable_files.push(path);
            }
        }
    }

    flush_staged_hunk(
        current_path.as_deref(),
        hunk_start,
        &mut hunk_added,
        multiline_detectors,
        &mut findings,
    );

    let metadata = ScanMetadata {
        files_scanned: scanned_files.len(),
        total_lines,
        excluded_files,
        unscannable_files: Vec::new(),
        suppressed_by_baseline: 0,
    };

    Ok(StagedScan {
        findings,
        metadata,
        undiffable_files,
    })
}

/// Result of parsing a staged diff. `undiffable_files` are paths git rendered
/// as binary (a real binary, or text marked `-diff` in .gitattributes); their
/// content never appears in the diff and must be read from the index instead.
struct StagedScan {
    findings: Vec<Finding>,
    metadata: ScanMetadata,
    undiffable_files: Vec<String>,
}

/// Scans the staged blob of each undiffable path via `git cat-file`.
///
/// Without this a `.gitattributes` entry like `*.env -diff` would hide a
/// staged secret completely: git emits only "Binary files ... differ" and the
/// scan would report the file as clean.
fn scan_undiffable_blobs(
    paths: &[String],
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, usize, Vec<String>), ScannerError> {
    let context = LineScanContext::new(line_detectors);
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut skipped = Vec::new();

    for path in paths {
        let output = std::process::Command::new("git")
            .args(["cat-file", "blob", &format!(":{path}")])
            .output()
            .map_err(|source| ScannerError::RunGitDiff { source })?;
        if !output.status.success() {
            skipped.push(path.clone());
            continue;
        }
        // Genuinely binary content (NUL bytes) is skipped, matching file mode.
        if output.stdout.contains(&0) {
            skipped.push(path.clone());
            continue;
        }
        let content = String::from_utf8_lossy(&output.stdout);
        let (blob_findings, blob_lines) =
            scan_content(&content, path, multiline_detectors, &context);
        findings.extend(blob_findings);
        total_lines += blob_lines;
    }

    Ok((findings, total_lines, skipped))
}

fn collect_files(dir_path: &str, files: &mut Vec<(String, Option<String>)>, root: &str) {
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_file() {
                if let Some(path_str) = path.to_str() {
                    files.push((path_str.to_string(), Some(root.to_string())));
                }
            } else if file_type.is_dir() && path.file_name().is_none_or(|name| name != ".git") {
                if let Some(path_str) = path.to_str() {
                    collect_files(path_str, files, root);
                }
            }
        }
    }
}

fn path_has_git_dir(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == ".git")
}

fn matches_exclude_patterns(
    path: &str,
    scan_roots: &[Option<String>],
    patterns: &[Pattern],
) -> bool {
    // Exclude patterns are written with forward slashes, so paths are matched
    // in that form: on Windows a scanned path is `target\\foo` and would
    // otherwise never match `target/**`.
    let forward_slashed = path.replace('\\', "/");
    let path = Path::new(forward_slashed.as_str());

    patterns.iter().any(|pattern| {
        pattern.matches_path(path)
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| pattern.matches(name))
            || scan_roots.iter().any(|root_opt| {
                root_opt
                    .as_deref()
                    .map(|root| root.replace('\\', "/"))
                    .and_then(|root| path.strip_prefix(&root).ok().map(Path::to_path_buf))
                    .is_some_and(|relative| pattern.matches_path(&relative))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Detector;
    use std::io::Cursor;

    fn make_detector(name: &str, pattern: &str, finding_type: &str, severity: &str) -> Detector {
        Detector::new(name, pattern, finding_type, severity, &[], &[], None).unwrap()
    }

    #[test]
    fn test_scan_stream_detects_secrets() {
        let content = "AWS Key: AKIAABCDEFGHIJKLMNOP\npassword = 'mySecretPassword'\n";
        let reader = Cursor::new(content);
        let detectors = [
            make_detector("AWS", r"\bAKIA[A-Z0-9]{16}\b", "AWS Key", "HIGH"),
            make_detector(
                "Password",
                r#"password\s*=\s*['"][^'"]+['"]"#,
                "Password",
                "HIGH",
            ),
        ];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, total_lines) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();

        assert_eq!(total_lines, 2);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .any(|finding| finding.finding_type == "AWS Key")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.finding_type == "Password")
        );
    }

    #[test]
    fn test_scan_stream_respects_inline_suppression() {
        let content = "password = 'secret123' # keywatch:ignore\n";
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "Password",
            r#"password\s*=\s*['"][^'"]+['"]"#,
            "Password",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, _) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert!(
            findings.is_empty(),
            "Suppressed line should produce no findings"
        );
    }

    #[test]
    fn test_scan_stream_multiline_detector() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwKVPSmwaFkYLv\n-----END RSA PRIVATE KEY-----\n";
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "PrivateKey",
            r"(?s)-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*-----END (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            "Private Key",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, _) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "Private Key");
    }

    #[test]
    fn test_scan_stream_large_input_chunked() {
        let mut content = String::new();
        for line_number in 0..2500 {
            content.push_str(&format!(
                "line {}: password = 'secret{}'\n",
                line_number, line_number
            ));
        }
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "Password",
            r#"password\s*=\s*['"][^'"]+['"]"#,
            "Password",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, total_lines) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert_eq!(total_lines, 2500);
        assert_eq!(
            findings.len(),
            2500,
            "Should find all 2500 secrets across chunks"
        );
    }

    #[test]
    fn test_prefilter_selects_detectors_with_overlapping_keywords() {
        // detectors.toml has genuinely overlapping keywords ("sk_" for Adyen,
        // "sk_test_" for Stripe). A non-overlapping search reports only the
        // shorter one and the longer detector silently never runs.
        let short = Detector::new(
            "Short",
            r"sk_\w+",
            "Short",
            "HIGH",
            &[],
            &["sk_".to_string()],
            None,
        )
        .unwrap();
        let long = Detector::new(
            "Long",
            r"sk_test_\w+",
            "Long",
            "HIGH",
            &[],
            &["sk_test_".to_string()],
            None,
        )
        .unwrap();
        let detectors = vec![&short, &long];
        let prefilter = KeywordPrefilter::new(&detectors);

        let mut candidates = Vec::new();
        prefilter.candidates_into("sk_test_51abcdef", &mut candidates);

        assert_eq!(
            candidates,
            vec![true, true],
            "both the shorter and longer keyword owners must be selected"
        );
    }

    #[test]
    fn test_scan_staged_diff_preserves_plus_prefixed_added_content() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/notes.txt b/notes.txt\n\
            index aabbcc0..ddeeff1 100644\n\
            --- /dev/null\n\
            +++ b/notes.txt\n\
            @@ -0,0 +1,3 @@\n\
            +SECRET_ONE plain\n\
            +++SECRET_TWO starts with pluses\n\
            +@@ SECRET_THREE looks like a hunk header\n";

        let StagedScan {
            findings, metadata, ..
        } = scan_staged_diff(Cursor::new(diff), &[], None, Path::new("."), &[], &line_detectors).unwrap();

        let summary: Vec<(String, usize)> = findings
            .iter()
            .map(|finding| (finding.matched_content.clone(), finding.line_number))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("SECRET_ONE".to_string(), 1),
                ("SECRET_TWO".to_string(), 2),
                ("SECRET_THREE".to_string(), 3),
            ],
            "added lines starting with '+', '@@' must be scanned as content"
        );
        assert!(findings.iter().all(|f| f.file_path == "notes.txt"));
        assert_eq!(metadata.files_scanned, 1);
    }

    #[test]
    fn test_scan_staged_diff_ignores_deleted_files_and_removed_lines() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/gone.txt b/gone.txt\n\
            deleted file mode 100644\n\
            --- a/gone.txt\n\
            +++ /dev/null\n\
            @@ -1,2 +0,0 @@\n\
            -SECRET_GONE\n\
            -goodbye\n";

        let StagedScan {
            findings, metadata, ..
        } = scan_staged_diff(Cursor::new(diff), &[], None, Path::new("."), &[], &line_detectors).unwrap();

        assert!(findings.is_empty(), "removed lines must not be scanned");
        assert_eq!(metadata.files_scanned, 0);
    }

    #[test]
    fn test_scan_staged_diff_attributes_multiple_files() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/first.txt b/first.txt\n\
            --- a/first.txt\n\
            +++ b/first.txt\n\
            @@ -0,0 +7 @@\n\
            +SECRET_A\n\
            diff --git a/second.txt b/second.txt\n\
            --- a/second.txt\n\
            +++ b/second.txt\n\
            @@ -0,0 +2 @@\n\
            +SECRET_B\n";

        let StagedScan {
            findings, metadata, ..
        } = scan_staged_diff(Cursor::new(diff), &[], None, Path::new("."), &[], &line_detectors).unwrap();

        let summary: Vec<(String, usize)> = findings
            .iter()
            .map(|finding| (finding.file_path.clone(), finding.line_number))
            .collect();
        assert_eq!(
            summary,
            vec![("first.txt".to_string(), 7), ("second.txt".to_string(), 2)]
        );
        assert_eq!(metadata.files_scanned, 2);
    }

    #[test]
    fn test_scan_staged_diff_queues_binary_files_for_blob_reading() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/img.png b/img.png\n\
            index aabbcc0..ddeeff1 100644\n\
            Binary files a/img.png and b/img.png differ\n";

        let staged = scan_staged_diff(Cursor::new(diff), &[], None, Path::new("."), &[], &line_detectors).unwrap();

        assert!(staged.findings.is_empty());
        assert!(
            staged.metadata.excluded_files.is_empty(),
            "an undiffable file is not 'excluded' — its blob still gets scanned"
        );
        assert_eq!(
            staged.undiffable_files,
            vec!["img.png".to_string()],
            "binary-rendered files must be queued for a direct blob read, or a \
             '-diff' gitattribute hides a staged secret entirely"
        );
    }

    #[test]
    fn test_scan_staged_diff_respects_excludes_for_binary_files() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/vendor/blob.bin b/vendor/blob.bin\n\
            Binary files a/vendor/blob.bin and b/vendor/blob.bin differ\n";
        let pattern = Pattern::new("vendor/**").unwrap();

        let staged =
            scan_staged_diff(Cursor::new(diff), &[pattern], None, Path::new("."), &[], &line_detectors).unwrap();

        assert!(
            staged.undiffable_files.is_empty(),
            "an excluded path must not be re-read from the index"
        );
        assert_eq!(
            staged.metadata.excluded_files,
            vec!["vendor/blob.bin".to_string()]
        );
    }

    #[test]
    fn test_scan_staged_diff_survives_non_utf8_content() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let mut diff: Vec<u8> = Vec::new();
        diff.extend_from_slice(b"diff --git a/legacy.csv b/legacy.csv\n");
        diff.extend_from_slice(b"--- a/legacy.csv\n");
        diff.extend_from_slice(b"+++ b/legacy.csv\n");
        diff.extend_from_slice(b"@@ -0,0 +1,2 @@\n");
        diff.extend_from_slice(b"+caf\xE9 latin-1 line\n");
        diff.extend_from_slice(b"+SECRET_AFTER_BINARYISH\n");

        let StagedScan { findings, .. } =
            scan_staged_diff(Cursor::new(diff), &[], None, Path::new("."), &[], &line_detectors).unwrap();

        assert_eq!(
            findings.len(),
            1,
            "non-UTF-8 content must not abort the scan"
        );
        assert_eq!(findings[0].line_number, 2);
    }

    #[test]
    fn test_scan_staged_diff_multiline_detector_uses_hunk_start_offset() {
        let detector = make_detector("Block", r"(?s)BEGIN KEY.*END KEY", "Test", "HIGH");
        let multiline_detectors = vec![&detector];
        let diff = "diff --git a/key.pem b/key.pem\n\
            --- a/key.pem\n\
            +++ b/key.pem\n\
            @@ -0,0 +5,3 @@\n\
            +BEGIN KEY\n\
            +material\n\
            +END KEY\n";

        let StagedScan { findings, .. } =
            scan_staged_diff(Cursor::new(diff), &[], None, Path::new("."), &multiline_detectors, &[]).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].line_number, 5,
            "multiline findings must use the hunk's post-image start line"
        );
        assert_eq!(findings[0].file_path, "key.pem");
    }

    #[test]
    fn test_parse_diff_target_path_unquotes_c_quoted_names() {
        assert_eq!(
            parse_diff_target_path("\"b/we\\\"ird.txt\"").as_deref(),
            Some("we\"ird.txt")
        );
        assert_eq!(
            parse_diff_target_path("\"b/tab\\there.txt\"").as_deref(),
            Some("tab\there.txt")
        );
        assert_eq!(
            parse_diff_target_path("b/plain.txt").as_deref(),
            Some("plain.txt")
        );
        assert_eq!(parse_diff_target_path("/dev/null"), None);
    }

    #[test]
    fn test_parse_binary_marker_path_unquotes_and_takes_post_image() {
        assert_eq!(
            parse_binary_marker_path(
                "Binary files \"a/one and two.bin\" and \"b/one and two.bin\" differ"
            ),
            "one and two.bin"
        );
        assert_eq!(
            parse_binary_marker_path("Binary files /dev/null and b/plain.bin differ"),
            "plain.bin"
        );
    }

    #[test]
    fn test_default_excluded_lockfiles_match_by_basename() {
        assert!(is_default_excluded_file("Cargo.lock"));
        assert!(is_default_excluded_file("nested/deep/package-lock.json"));
        assert!(is_default_excluded_file("vendor\\yarn.lock"));
        assert!(!is_default_excluded_file("src/Cargo.toml"));
        assert!(!is_default_excluded_file("mylock"));
    }
}
