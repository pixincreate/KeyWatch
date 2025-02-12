use crate::cli::CliOptions;
use crate::detector::initialize_detectors; // Instead of patterns::get_patterns
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

    // Gather target files from --file or --dir.
    if let Some(ref file_path) = options.file {
        target_paths.push(file_path.clone());
    } else if let Some(ref dir_path) = options.dir {
        collect_files(dir_path, &mut target_paths);
    }

    // Initialize our improved detectors
    let detectors = initialize_detectors();

    for path in target_paths {
        // Example exclusion: skip .git files
        if path.contains(".git") {
            excluded_files.push(path.clone());
            continue;
        }

        files_scanned += 1;
        if let Ok(file) = fs::File::open(&path) {
            let reader = BufReader::new(file);
            for (line_number, line_result) in reader.lines().enumerate() {
                total_lines += 1;
                if let Ok(line) = line_result {
                    // Run each detector against the current line.
                    for detector in detectors.iter() {
                        if let Some(mat) = detector.regex.find(&line) {
                            let matched_content = mat.as_str().to_string();
                            let finding = Finding {
                                file_path: path.clone(),
                                line_number: line_number + 1,
                                finding_type: detector.finding_type.clone(),
                                severity: detector.severity.clone(),
                                matched_content,
                                plugin_name: detector.name.clone(),
                            };
                            findings.push(finding);
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

/// Recursively collect files from a directory.
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
