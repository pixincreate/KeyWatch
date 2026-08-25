use crate::cli::ScanArgs;
use crate::config::KeywatchConfig;
use crate::detector::{Detector, initialize_detectors, initialize_trusted_detectors};
use crate::report::{Finding, ScanMetadata};
use glob::Pattern;
use rayon::prelude::*;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

mod error;

pub use error::ScannerError;

const INLINE_SUPPRESS: &str = "keywatch:ignore";

fn is_inline_suppressed(line: &str) -> bool {
    line.to_lowercase().contains(INLINE_SUPPRESS)
}

fn is_allowlisted(matched: &str, detector: &Detector) -> bool {
    detector
        .allowlist
        .iter()
        .any(|pattern| pattern.is_match(matched))
}

fn scan_line_detectors(
    line: &str,
    line_number: usize,
    path: &str,
    line_detectors: &[&Detector],
    line_is_suppressed: bool,
    findings: &mut Vec<Finding>,
) {
    if line_is_suppressed {
        return;
    }

    for detector in line_detectors {
        if detector.has_keywords(line) {
            for mat in detector.regex.find_iter(line) {
                if !is_allowlisted(mat.as_str(), detector)
                    && detector.has_sufficient_entropy(mat.as_str())
                {
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
}

fn scan_multiline_chunk(
    chunk: &str,
    line_offset: usize,
    path: &str,
    multiline_detectors: &[&Detector],
    findings: &mut Vec<Finding>,
) {
    for detector in multiline_detectors {
        if detector.has_keywords(chunk) {
            for mat in detector.regex.find_iter(chunk) {
                let line_in_chunk = chunk[..mat.start()].matches('\n').count() + 1;
                let line_content = chunk
                    .lines()
                    .nth(line_in_chunk.saturating_sub(1))
                    .unwrap_or_default();
                let line_is_suppressed = is_inline_suppressed(line_content);

                if !line_is_suppressed
                    && !is_allowlisted(mat.as_str(), detector)
                    && detector.has_sufficient_entropy(mat.as_str())
                {
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
    line_detectors: &[&Detector],
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut total_lines = 0;

    scan_multiline_chunk(content, 0, path, multiline_detectors, &mut findings);

    for (line_idx, line) in content.lines().enumerate() {
        total_lines += 1;
        scan_line_detectors(
            line,
            line_idx + 1,
            path,
            line_detectors,
            is_inline_suppressed(line),
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

    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut buffer: Vec<String> = Vec::with_capacity(CHUNK_SIZE + OVERLAP_LINES);
    let mut line_offset = 0;

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
            line_detectors,
            is_inline_suppressed(&line),
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

pub fn run_scan(
    args: &ScanArgs,
    config: Option<&KeywatchConfig>,
) -> Result<(Vec<Finding>, ScanMetadata), ScannerError> {
    let mut detectors = if args.no_config_discovery {
        initialize_trusted_detectors()
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

    if args.git_history {
        let git_root = args
            .paths
            .first()
            .map(Path::new)
            .unwrap_or_else(|| Path::new("."));
        let mut child = std::process::Command::new("git")
            .current_dir(git_root)
            .args([
                "-c",
                "diff.external=",
                "-c",
                "color.ui=false",
                "log",
                "-p",
                "-U0",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|source| ScannerError::RunGitLog { source })?;

        let stdout = child.stdout.take().ok_or(ScannerError::CaptureGitStdout)?;
        let reader = BufReader::new(stdout);
        let (findings, total_lines) = scan_stream(
            reader,
            "<git-history>",
            &multiline_detectors,
            &line_detectors,
        )?;

        let status = child
            .wait()
            .map_err(|source| ScannerError::GitProcess { source })?;
        if !status.success() {
            return Err(ScannerError::GitLogNonZero);
        }

        let metadata = ScanMetadata {
            files_scanned: 1,
            total_lines,
            excluded_files: Vec::new(),
        };

        return Ok((findings, metadata));
    }

    if args.staged {
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
            "diff",
            "--cached",
            "-U0",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--",
        ]);
        command.args(&args.paths);
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|source| ScannerError::RunGitDiff { source })?;

        let stdout = child.stdout.take().ok_or(ScannerError::CaptureGitStdout)?;
        let reader = BufReader::new(stdout);
        let scan_result = scan_staged_diff(
            reader,
            &exclude_patterns,
            &multiline_detectors,
            &line_detectors,
        );
        if scan_result.is_err() {
            // Reap git instead of leaving it writing into a closed pipe.
            let _ = child.kill();
        }
        let wait_result = child.wait();

        let (findings, metadata) = scan_result?;
        let status = wait_result.map_err(|source| ScannerError::GitProcess { source })?;
        if !status.success() {
            return Err(ScannerError::GitDiffNonZero);
        }

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

    let results: Vec<(Vec<Finding>, usize, usize, Option<String>)> = unique_paths
        .into_par_iter()
        .map(|(path, roots)| {
            if path_has_git_dir(Path::new(&path)) {
                return (Vec::new(), 0, 0, Some(path));
            }

            if matches_exclude_patterns(&path, &roots, &exclude_patterns) {
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

            let (file_findings, file_lines) =
                scan_content(&full_content, &path, &multiline_detectors, &line_detectors);

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

    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line_number.cmp(&b.line_number))
    });

    let metadata = ScanMetadata {
        files_scanned,
        total_lines,
        excluded_files,
    };

    Ok((findings, metadata))
}

fn compile_exclude_patterns(
    args: &ScanArgs,
    config: Option<&KeywatchConfig>,
) -> Result<Vec<Pattern>, ScannerError> {
    let mut exclude_patterns: Vec<Pattern> = args
        .exclude
        .as_ref()
        .map(|exclude_str| {
            exclude_str
                .split(',')
                .filter(|pattern| !pattern.trim().is_empty())
                .map(|pattern| {
                    Pattern::new(pattern.trim()).map_err(|source| {
                        ScannerError::InvalidExcludePattern {
                            pattern: pattern.to_string(),
                            source,
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

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

fn parse_hunk_new_start(header: &str) -> usize {
    header
        .split_whitespace()
        .find(|token| token.starts_with('+'))
        .and_then(|token| {
            token[1..]
                .split(',')
                .next()
                .and_then(|start| start.parse().ok())
        })
        .unwrap_or(0)
}

fn parse_diff_target_path(target: &str) -> Option<String> {
    let target = target.trim_end();
    if target == "/dev/null" {
        return None;
    }
    let target = target.trim_matches('"');
    let target = target.strip_prefix("b/").unwrap_or(target);
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
/// post-image side, for surfacing skipped files in `excluded_files`.
fn parse_binary_marker_path(marker: &str) -> String {
    marker
        .strip_suffix(" differ")
        .and_then(|paths| paths.rsplit(" and ").next())
        .map(|target| target.strip_prefix("b/").unwrap_or(target))
        .unwrap_or(marker)
        .to_string()
}

/// Scans only the added lines of the staged diff, attributing findings to the
/// real file path and post-image line number so `--baseline` entries match.
/// Hunk state is tracked because added content may itself start with "+".
/// Lines are decoded lossily so one non-UTF-8 file cannot abort the scan.
fn scan_staged_diff<ReaderType: BufRead>(
    mut reader: ReaderType,
    exclude_patterns: &[Pattern],
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, ScanMetadata), ScannerError> {
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut scanned_files: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut excluded_files: Vec<String> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut in_hunk = false;
    let mut next_line_number = 0;
    let mut hunk_start = 0;
    let mut hunk_added: Vec<String> = Vec::new();
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
                    line_detectors,
                    is_inline_suppressed(content),
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
                Some(path) if matches_exclude_patterns(&path, &[], exclude_patterns) => {
                    excluded_files.push(path);
                    None
                }
                other => other,
            };
            continue;
        }

        // A `-diff` gitattribute (or a true binary) yields no hunks; surface
        // the skipped file instead of silently reporting it as clean.
        if let Some(marker) = line.strip_prefix("Binary files ") {
            excluded_files.push(parse_binary_marker_path(marker));
        }
    }

    flush_staged_hunk(
        current_path.as_deref(),
        hunk_start,
        &mut hunk_added,
        multiline_detectors,
        &mut findings,
    );

    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line_number.cmp(&b.line_number))
    });

    let metadata = ScanMetadata {
        files_scanned: scanned_files.len(),
        total_lines,
        excluded_files,
    };

    Ok((findings, metadata))
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
    let path = Path::new(path);

    patterns.iter().any(|pattern| {
        pattern.matches_path(path)
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| pattern.matches(name))
            || scan_roots.iter().any(|root_opt| {
                root_opt
                    .as_deref()
                    .and_then(|root| path.strip_prefix(root).ok())
                    .is_some_and(|relative| pattern.matches_path(relative))
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

        let (findings, metadata) =
            scan_staged_diff(Cursor::new(diff), &[], &[], &line_detectors).unwrap();

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

        let (findings, metadata) =
            scan_staged_diff(Cursor::new(diff), &[], &[], &line_detectors).unwrap();

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

        let (findings, metadata) =
            scan_staged_diff(Cursor::new(diff), &[], &[], &line_detectors).unwrap();

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
    fn test_scan_staged_diff_surfaces_binary_files_as_excluded() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/img.png b/img.png\n\
            index aabbcc0..ddeeff1 100644\n\
            Binary files a/img.png and b/img.png differ\n";

        let (findings, metadata) =
            scan_staged_diff(Cursor::new(diff), &[], &[], &line_detectors).unwrap();

        assert!(findings.is_empty());
        assert_eq!(
            metadata.excluded_files,
            vec!["img.png".to_string()],
            "files git renders as binary must be surfaced, not silently clean"
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

        let (findings, _) =
            scan_staged_diff(Cursor::new(diff), &[], &[], &line_detectors).unwrap();

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

        let (findings, _) =
            scan_staged_diff(Cursor::new(diff), &[], &multiline_detectors, &[]).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].line_number, 5,
            "multiline findings must use the hunk's post-image start line"
        );
        assert_eq!(findings[0].file_path, "key.pem");
    }
}
