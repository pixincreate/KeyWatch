use crate::cli::ScanArgs;
use crate::config::KeywatchConfig;
use crate::detector::{Detector, initialize_detectors, initialize_trusted_detectors};
use crate::report::{Finding, ScanMetadata};
use glob::Pattern;
use rayon::prelude::*;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

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

fn scan_stream<R: BufRead>(
    reader: R,
    path: &str,
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, usize), String> {
    const CHUNK_SIZE: usize = 1000;
    const OVERLAP_LINES: usize = 50;

    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut buffer: Vec<String> = Vec::with_capacity(CHUNK_SIZE + OVERLAP_LINES);
    let mut line_offset = 0;

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| format!("Read error on {}: {}", path, e))?;
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
) -> Result<(Vec<Finding>, ScanMetadata), String> {
    let mut detectors = if args.no_config_discovery {
        initialize_trusted_detectors()
    } else {
        initialize_detectors()
    }
    .map_err(|err| err.to_string())?;

    if let Some(cfg) = config {
        cfg.apply_to(&mut detectors)?;
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
                "log",
                "-p",
                "-U0",
                "--no-ext-diff",
                "--no-textconv",
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|err| format!("Failed to run git log: {}", err))?;

        let stdout = child.stdout.take().ok_or("Failed to capture git stdout")?;
        let reader = BufReader::new(stdout);
        let (findings, total_lines) = scan_stream(
            reader,
            "<git-history>",
            &multiline_detectors,
            &line_detectors,
        )?;

        let status = child
            .wait()
            .map_err(|e| format!("git process error: {}", e))?;
        if !status.success() {
            return Err("git log exited with non-zero status".to_string());
        }

        let metadata = ScanMetadata {
            files_scanned: 1,
            total_lines,
            excluded_files: Vec::new(),
        };

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

    let mut exclude_patterns: Vec<Pattern> = args
        .exclude
        .as_ref()
        .map(|exclude_str| {
            exclude_str
                .split(',')
                .filter(|pattern| !pattern.trim().is_empty())
                .map(|pattern| {
                    Pattern::new(pattern.trim())
                        .map_err(|err| format!("Invalid exclude pattern '{}': {}", pattern, err))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    if let Some(excludes) = config.and_then(|cfg| cfg.exclude.as_ref()) {
        for pattern_str in excludes {
            exclude_patterns.push(Pattern::new(pattern_str).map_err(|err| {
                format!("Invalid config exclude pattern '{}': {}", pattern_str, err)
            })?);
        }
    }

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

    fn make_detector(name: &str, pattern: &str, ftype: &str, sev: &str) -> Detector {
        Detector::new(name, pattern, ftype, sev, &[], &[], None).unwrap()
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
        let (multi, line): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|d| d.regex.as_str().contains("(?s)"));

        let (findings, lines) = scan_stream(reader, "<test>", &multi, &line).unwrap();

        assert_eq!(lines, 2);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.finding_type == "AWS Key"));
        assert!(findings.iter().any(|f| f.finding_type == "Password"));
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
        let (multi, line): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|d| d.regex.as_str().contains("(?s)"));

        let (findings, _) = scan_stream(reader, "<test>", &multi, &line).unwrap();
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
        let (multi, line): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|d| d.regex.as_str().contains("(?s)"));

        let (findings, _) = scan_stream(reader, "<test>", &multi, &line).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "Private Key");
    }

    #[test]
    fn test_scan_stream_large_input_chunked() {
        let mut content = String::new();
        for i in 0..2500 {
            content.push_str(&format!("line {}: password = 'secret{}'\n", i, i));
        }
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "Password",
            r#"password\s*=\s*['"][^'"]+['"]"#,
            "Password",
            "HIGH",
        )];
        let (multi, line): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|d| d.regex.as_str().contains("(?s)"));

        let (findings, lines) = scan_stream(reader, "<test>", &multi, &line).unwrap();
        assert_eq!(lines, 2500);
        assert_eq!(
            findings.len(),
            2500,
            "Should find all 2500 secrets across chunks"
        );
    }
}
