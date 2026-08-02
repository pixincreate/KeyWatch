use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, str::FromStr};
mod sarif;

pub use sarif::create_sarif_report;

#[derive(Serialize, Clone, PartialEq, Copy, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
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

/// Error returned when a string cannot be parsed as a [`Severity`].
#[derive(Debug, PartialEq)]
pub struct ParseSeverityError {
    pub input: String,
}

impl fmt::Display for ParseSeverityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
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

/// Deserialize [`Severity`] from a string using the existing case-insensitive
/// [`FromStr`] implementation. Serialization output (`UPPERCASE`) is governed
/// by the `#[serde(rename_all = "UPPERCASE")]` derive above and is not
/// affected by this impl.
impl<'de> Deserialize<'de> for Severity {
    fn deserialize<DeserializerType: Deserializer<'de>>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error> {
        struct SeverityVisitor;

        impl Visitor<'_> for SeverityVisitor {
            type Value = Severity;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one of CRITICAL, HIGH, MEDIUM, LOW (case-insensitive)")
            }

            fn visit_str<ErrorType: de::Error>(self, value: &str) -> Result<Severity, ErrorType> {
                Severity::from_str(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SeverityVisitor)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
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
