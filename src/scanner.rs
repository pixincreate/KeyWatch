use crate::cli::CliOptions;
use crate::detector::initialize_detectors;
use crate::report::{Finding, ScanMetadata};
use glob::Pattern;
use std::fs;
use std::path::Path;

pub fn run_scan(options: &CliOptions) -> Result<(Vec<Finding>, ScanMetadata), String> {
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let mut total_lines = 0;
    let mut excluded_files = Vec::new();

    let mut target_paths = Vec::new();

    if let Some(ref file_path) = options.file {
        target_paths.push(file_path.clone());
    } else if let Some(ref dir_path) = options.dir {
        collect_files(dir_path, &mut target_paths);
    }

    let detectors = initialize_detectors().map_err(|err| err.to_string())?;
    let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
        .iter()
        .partition(|detector| detector.regex.as_str().contains("(?s)"));

    let exclude_patterns: Vec<Pattern> = options
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

    for path in target_paths {
        if path_has_git_dir(Path::new(&path)) {
            excluded_files.push(path);
            continue;
        }

        let should_exclude =
            matches_exclude_patterns(&path, options.dir.as_deref(), &exclude_patterns);

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

fn collect_files(dir_path: &str, files: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(path_str) = path.to_str() {
                    files.push(path_str.to_string());
                }
            } else if path.is_dir()
                && path.file_name().is_none_or(|name| name != ".git")
                && let Some(path_str) = path.to_str()
            {
                collect_files(path_str, files);
            }
        }
    }
}

fn path_has_git_dir(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == ".git")
}

fn matches_exclude_patterns(path: &str, scan_root: Option<&str>, patterns: &[Pattern]) -> bool {
    let path = Path::new(path);

    patterns.iter().any(|pattern| {
        pattern.matches_path(path)
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| pattern.matches(name))
            || scan_root
                .and_then(|root| path.strip_prefix(root).ok())
                .is_some_and(|relative| pattern.matches_path(relative))
    })
}
