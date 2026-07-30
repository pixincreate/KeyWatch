use serde::Serialize;
use std::{collections::HashMap, fmt, str::FromStr};

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

/// Generate a SARIF 2.1.0 report from findings.
pub fn create_sarif_report(
    findings: Vec<Finding>,
    _metadata: ScanMetadata,
    scan_time: String,
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct SarifLog {
        #[serde(rename = "$schema")]
        schema: &'static str,
        version: &'static str,
        runs: Vec<SarifRun>,
    }

    #[derive(Serialize)]
    struct SarifRun {
        tool: SarifTool,
        results: Vec<SarifResult>,
        properties: HashMap<String, serde_json::Value>,
    }

    #[derive(Serialize)]
    struct SarifTool {
        driver: SarifDriver,
    }

    #[derive(Serialize)]
    struct SarifDriver {
        name: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        information_uri: &'static str,
        semantic_version: Option<String>,
    }

    #[derive(Serialize)]
    struct SarifResult {
        rule_id: String,
        level: &'static str,
        message: SarifMessage,
        locations: Vec<SarifLocation>,
        properties: HashMap<String, serde_json::Value>,
    }

    #[derive(Serialize)]
    struct SarifMessage {
        text: String,
    }

    #[derive(Serialize)]
    struct SarifLocation {
        physical_location: SarifPhysicalLocation,
    }

    #[derive(Serialize)]
    struct SarifPhysicalLocation {
        artifact_location: SarifArtifactLocation,
        region: SarifRegion,
    }

    #[derive(Serialize)]
    struct SarifArtifactLocation {
        uri: String,
    }

    #[derive(Serialize)]
    struct SarifRegion {
        start_line: usize,
    }

    fn severity_to_sarif_level(s: Severity) -> &'static str {
        match s {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        }
    }

    let results: Vec<SarifResult> = findings
        .into_iter()
        .map(|f| {
            let rule_id = f.finding_type;
            let level = severity_to_sarif_level(f.severity);
            let rule_id_clone = rule_id.clone();
            let severity_str = format!("{:?}", f.severity);
            let uri = f.file_path;
            let start_line = f.line_number;

            let mut properties = HashMap::new();
            properties.insert(
                "precision".to_string(),
                serde_json::Value::String("very-high".to_string()),
            );
            properties.insert(
                "severity".to_string(),
                serde_json::Value::String(severity_str),
            );

            SarifResult {
                rule_id,
                level,
                message: SarifMessage {
                    text: format!("Potential {} detected", rule_id_clone),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri },
                        region: SarifRegion { start_line },
                    },
                }],
                properties,
            }
        })
        .collect();

    let status = if results.is_empty() { "pass" } else { "fail" };

    let mut properties = HashMap::new();
    properties.insert(
        "status".to_string(),
        serde_json::Value::String(status.to_string()),
    );
    properties.insert("scanTime".to_string(), serde_json::Value::String(scan_time));

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "KeyWatch",
                    version: option_env!("CARGO_PKG_VERSION").map(|v| v.to_string()),
                    information_uri: "https://github.com/pixincreate/KeyWatch",
                    semantic_version: option_env!("CARGO_PKG_VERSION").map(|v| v.to_string()),
                },
            },
            results,
            properties,
        }],
    };

    serde_json::to_string_pretty(&log)
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
