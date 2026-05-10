use serde::Serialize;

#[derive(Serialize, Clone, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn from_string(s: &str) -> Severity {
        match s.to_uppercase().as_str() {
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    Pass,
    Fail,
}

/// Represents a single secret finding.
#[derive(Serialize, Clone)]
pub struct Finding {
    pub file_path: String,
    pub line_number: usize,
    pub finding_type: String,
    pub severity: Severity,
    pub matched_content: String,
    pub plugin_name: String,
}

/// Metadata about the scanning performed.
#[derive(Serialize, Clone)]
pub struct ScanMetadata {
    pub files_scanned: usize,
    pub total_lines: usize,
    pub excluded_files: Vec<String>,
}

/// The overall report.
#[derive(Serialize)]
pub struct Report {
    pub status: ScanStatus,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub total_lines: usize,
    pub excluded_files: Vec<String>,
    pub scan_time: String,
}

/// create_report builds the final JSON report based on findings and metadata.
pub fn create_report(
    findings: Vec<Finding>,
    metadata: ScanMetadata,
    scan_time: String,
) -> Result<String, serde_json::Error> {
    let status = if findings.is_empty() {
        ScanStatus::Pass
    } else {
        ScanStatus::Fail
    };
    let report = Report {
        status,
        findings,
        files_scanned: metadata.files_scanned,
        total_lines: metadata.total_lines,
        excluded_files: metadata.excluded_files,
        scan_time,
    };

    serde_json::to_string_pretty(&report)
}

pub fn get_severity_counts(findings: &[Finding]) -> (usize, usize, usize) {
    let mut counts = (0, 0, 0);
    for finding in findings {
        counts = match finding.severity {
            Severity::High => (counts.0 + 1, counts.1, counts.2),
            Severity::Medium => (counts.0, counts.1 + 1, counts.2),
            Severity::Low => (counts.0, counts.1, counts.2 + 1),
        };
    }
    counts
}
