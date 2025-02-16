use crate::cli::CliOptions;
use crate::detector::initialize_detectors;
use crate::report::{Finding, ScanMetadata};
use std::fs;
use std::io::{BufRead, BufReader};

/// run_scan executes the secret scan based on the provided CLI options.
/// Returns a vector of findings and metadata about the scan.
pub fn run_scan(options: &CliOptions) -> (Vec<Finding>, ScanMetadata) {
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let mut total_lines = 0;
    let mut excluded_files = Vec::new();

    let mut target_paths = Vec::new();

    // Collect target files from --file or --dir.
    if let Some(ref file_path) = options.file {
        target_paths.push(file_path.clone());
    } else if let Some(ref dir_path) = options.dir {
        collect_files(dir_path, &mut target_paths);
    }

    // Initialize our improved detectors
    let detectors = initialize_detectors();

    for path in target_paths {
        // Exclude files whose path contains ".git"
        if path.contains(".git") {
            excluded_files.push(path.clone());
            continue;
        }

        files_scanned += 1;

        // Read entire file content once.
        let full_content = fs::read_to_string(&path).unwrap_or_default();

        // First pass: apply detectors that require multi-line scanning.
        for detector in detectors.iter() {
            // Use a simple flag choice: if the detector regex pattern contains "(?s)"
            if detector.regex.as_str().contains("(?s)") {
                if let Some(mat) = detector.regex.find(&full_content) {
                    // Count the line number by counting newline characters before the match.
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
        }

        // Second pass: process file line-by-line for single‑line detectors.
        if let Ok(file) = fs::File::open(&path) {
            let reader = BufReader::new(file);
            for (line_idx, line_result) in reader.lines().enumerate() {
                total_lines += 1;
                if let Ok(line) = line_result {
                    // For each detector that is NOT marked for multi-line scanning.
                    for detector in detectors.iter() {
                        if !detector.regex.as_str().contains("(?s)") {
                            if let Some(mat) = detector.regex.find(&line) {
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
            }
        }
    }

    let metadata = ScanMetadata {
        files_scanned,
        total_lines,
        excluded_files,
    };

    (findings, metadata)
}

/// Recursively collect files from the given directory.
fn collect_files(dir_path: &str, files: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(path_str) = path.to_str() {
                    files.push(path_str.to_string());
                }
            } else if path.is_dir() {
                if let Some(path_str) = path.to_str() {
                    collect_files(path_str, files);
                }
            }
        }
    }
}
