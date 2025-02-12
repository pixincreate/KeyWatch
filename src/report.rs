use serde::Serialize;

/// Represents a single secret finding.
#[derive(Serialize)]
pub struct Finding {
    pub file_path: String,
    pub line_number: usize,
    pub finding_type: String,
    pub severity: String,
    pub matched_content: String,
    pub plugin_name: String,
}

/// Metadata about the scanning performed.
#[derive(Serialize)]
pub struct ScanMetadata {
    pub files_scanned: usize,
    pub total_lines: usize,
    pub excluded_files: Vec<String>,
}

/// ReportMetadata bundles scan metadata with scan_time.
#[derive(Serialize)]
pub struct ReportMetadata {
    pub files_scanned: usize,
    pub total_lines: usize,
    pub excluded_files: Vec<String>,
    pub scan_time: String,
}

/// The overall report.
#[derive(Serialize)]
pub struct Report {
    pub status: String,
    pub findings: Vec<Finding>,
    pub scan_metadata: ReportMetadata,
}

/// create_report builds the final JSON report based on findings and metadata.
pub fn create_report(findings: Vec<Finding>, metadata: ScanMetadata, scan_time: String) -> String {
    let status = if findings.is_empty() { "PASS" } else { "FAIL" };
    let report_metadata = ReportMetadata {
        files_scanned: metadata.files_scanned,
        total_lines: metadata.total_lines,
        excluded_files: metadata.excluded_files,
        scan_time,
    };
    let report = Report {
        status: status.to_string(),
        findings,
        scan_metadata: report_metadata,
    };

    serde_json::to_string_pretty(&report).unwrap()
}
