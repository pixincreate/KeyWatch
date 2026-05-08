use crate::cli::ScanArgs;
use crate::detector::initialize_detectors;
use crate::report::{Finding, ScanMetadata};
use glob::Pattern;
use std::fs;
use std::path::Path;

pub fn run_scan(args: &ScanArgs) -> Result<(Vec<Finding>, ScanMetadata), String> {
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let mut total_lines = 0;
    let mut excluded_files = Vec::new();

    let mut target_paths = Vec::new();

    for path_str in &args.paths {
        let path = Path::new(path_str);
        if path.is_file() {
            target_paths.push((path_str.clone(), None));
        } else if path.is_dir() {
            collect_files(path_str, &mut target_paths, path_str);
        } else {
            // Push anyway, let read handle it or ignore
            target_paths.push((path_str.clone(), None));
        }
    }

    target_paths.sort_by(|a, b| a.0.cmp(&b.0));

    let mut unique_paths: Vec<(String, Vec<Option<String>>)> = Vec::new();
    for (path, root) in target_paths {
        if let Some(last) = unique_paths.last_mut() {
            if last.0 == path {
                if !last.1.contains(&root) {
                    last.1.push(root);
                }
                continue;
            }
        }
        unique_paths.push((path, vec![root]));
    }

    let detectors = initialize_detectors().map_err(|err| err.to_string())?;
    let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
        .iter()
        .partition(|detector| detector.regex.as_str().contains("(?s)"));

    let exclude_patterns: Vec<Pattern> = args
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

    for (path, roots) in unique_paths {
        if path_has_git_dir(Path::new(&path)) {
            excluded_files.push(path);
            continue;
        }

        let should_exclude = matches_exclude_patterns(&path, &roots, &exclude_patterns);

        if should_exclude {
            excluded_files.push(path);
            continue;
        }

        let full_content = match fs::read(&path) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(content) => content,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        files_scanned += 1;

        for detector in &multiline_detectors {
            if let Some(mat) = detector.regex.find(&full_content) {
                let line_number = full_content[..mat.start()].matches('\n').count() + 1;
                findings.push(Finding {
                    file_path: path.clone(),
                    line_number,
                    matched_content: mat.as_str().to_string(),
                    finding_type: detector.finding_type.clone(),
                    severity: detector.severity.clone(),
                    plugin_name: detector.name.clone(),
                });
            }
        }

        for (line_idx, line) in full_content.lines().enumerate() {
            total_lines += 1;
            for detector in &line_detectors {
                if let Some(mat) = detector.regex.find(line) {
                    findings.push(Finding {
                        file_path: path.clone(),
                        line_number: line_idx + 1,
                        matched_content: mat.as_str().to_string(),
                        finding_type: detector.finding_type.clone(),
                        severity: detector.severity.clone(),
                        plugin_name: detector.name.clone(),
                    });
                }
            }
        }
    }

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
            let path = entry.path();
            if path.is_file() {
                if let Some(path_str) = path.to_str() {
                    files.push((path_str.to_string(), Some(root.to_string())));
                }
            } else if path.is_dir()
                && path.file_name().is_none_or(|name| name != ".git")
                && let Some(path_str) = path.to_str()
            {
                collect_files(path_str, files, root);
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
