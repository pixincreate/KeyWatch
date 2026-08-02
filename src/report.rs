use serde::Serialize;
use std::{fmt, str::FromStr};

#[derive(Serialize, Clone, PartialEq, Copy, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Error returned when a string cannot be parsed as a [`Severity`].
#[derive(Debug, PartialEq)]
pub struct ParseSeverityError {
    pub input: String,
}

impl fmt::Display for ParseSeverityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid severity '{}': expected one of CRITICAL, HIGH, MEDIUM, LOW",
            self.input
        )
    }
}

impl std::error::Error for ParseSeverityError {}

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_uppercase().as_str() {
            "CRITICAL" => Ok(Severity::Critical),
            "HIGH" => Ok(Severity::High),
            "MEDIUM" => Ok(Severity::Medium),
            "LOW" => Ok(Severity::Low),
            _ => Err(ParseSeverityError {
                input: value.to_string(),
            }),
        }
    }
}

impl Severity {
    /// Return the canonical uppercase string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    Pass,
    Fail,
}

#[derive(Serialize, Clone)]
pub struct Finding {
    pub file_path: String,
    pub line_number: usize,
    pub finding_type: String,
    pub severity: Severity,
    pub matched_content: String,
    pub plugin_name: String,
}

#[derive(Serialize, Clone)]
pub struct ScanMetadata {
    pub files_scanned: usize,
    pub total_lines: usize,
    pub excluded_files: Vec<String>,
}

#[derive(Serialize)]
pub struct Report {
    pub status: ScanStatus,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub total_lines: usize,
    pub excluded_files: Vec<String>,
    pub scan_time: String,
}

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

pub fn get_severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0);
    for finding in findings {
        counts = match finding.severity {
            Severity::Critical => (counts.0 + 1, counts.1, counts.2, counts.3),
            Severity::High => (counts.0, counts.1 + 1, counts.2, counts.3),
            Severity::Medium => (counts.0, counts.1, counts.2 + 1, counts.3),
            Severity::Low => (counts.0, counts.1, counts.2, counts.3 + 1),
        };
    }
    counts
}
