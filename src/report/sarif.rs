use super::{Finding, ScanMetadata, Severity};
use serde::Serialize;
use std::collections::BTreeMap;

fn artifact_uri(path: &str) -> String {
    let normalized = if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    let mut uri = if std::path::Path::new(path).is_absolute() {
        if cfg!(windows) && normalized.starts_with("//") {
            "file:".to_string()
        } else if cfg!(windows) {
            "file:///".to_string()
        } else {
            "file://".to_string()
        }
    } else {
        String::new()
    };
    for (index, byte) in normalized.bytes().enumerate() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/')
            || (cfg!(windows)
                && index == 1
                && byte == b':'
                && normalized.as_bytes()[0].is_ascii_alphabetic())
        {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(uri, "%{byte:02X}").expect("Writing to a String cannot fail");
        }
    }
    uri
}

/// Generate a SARIF 2.1.0 report from findings.
pub fn create_sarif_report(
    findings: Vec<Finding>,
    metadata: ScanMetadata,
    scan_time: String,
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifLog {
        #[serde(rename = "$schema")]
        schema: &'static str,
        version: &'static str,
        runs: Vec<SarifRun>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifRun {
        tool: SarifTool,
        results: Vec<SarifResult>,
        properties: BTreeMap<String, serde_json::Value>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifTool {
        driver: SarifDriver,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifDriver {
        name: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        information_uri: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        semantic_version: Option<String>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifResult {
        rule_id: String,
        level: &'static str,
        message: SarifMessage,
        locations: Vec<SarifLocation>,
        properties: BTreeMap<String, serde_json::Value>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifMessage {
        text: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifLocation {
        physical_location: SarifPhysicalLocation,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifPhysicalLocation {
        artifact_location: SarifArtifactLocation,
        region: SarifRegion,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifArtifactLocation {
        uri: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifRegion {
        start_line: usize,
    }

    fn severity_to_sarif_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        }
    }

    let results: Vec<SarifResult> = findings
        .into_iter()
        .map(|finding| {
            let rule_id = finding.finding_type;
            let level = severity_to_sarif_level(finding.severity);
            let rule_id_clone = rule_id.clone();
            let severity_str = finding.severity.as_str();
            let uri = artifact_uri(&finding.file_path);
            let start_line = finding.line_number;

            // No per-rule confidence model exists, so no `precision` claim is
            // made: a blanket "very-high" on entropy-gated LOW rules was a
            // false statement to SARIF consumers.
            let mut properties = BTreeMap::new();
            properties.insert(
                "severity".to_string(),
                serde_json::Value::String(severity_str.to_string()),
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

    let finding_status = if results.is_empty() { "pass" } else { "fail" };
    let status = if metadata.is_complete() {
        finding_status
    } else {
        "incomplete"
    };

    // Scan counts only: the BTreeMap serializes in key order, so the payload
    // is deterministic, and no matched content enters the run metadata.
    let mut properties = BTreeMap::new();
    properties.insert(
        "detectorFingerprint".to_string(),
        serde_json::json!(metadata.detector_fingerprint),
    );
    properties.insert(
        "findingStatus".to_string(),
        serde_json::json!(finding_status),
    );
    properties.insert(
        "coverage".to_string(),
        serde_json::json!(if metadata.is_complete() {
            "complete"
        } else {
            "incomplete"
        }),
    );
    properties.insert(
        "coverageWarnings".to_string(),
        serde_json::json!(metadata.coverage_warnings),
    );
    properties.insert(
        "status".to_string(),
        serde_json::Value::String(status.to_string()),
    );
    properties.insert("scanTime".to_string(), serde_json::Value::String(scan_time));
    properties.insert(
        "filesScanned".to_string(),
        serde_json::Value::from(metadata.files_scanned),
    );
    properties.insert(
        "totalLines".to_string(),
        serde_json::Value::from(metadata.total_lines),
    );
    properties.insert(
        "excludedFiles".to_string(),
        serde_json::Value::from(metadata.excluded_files.len()),
    );
    properties.insert(
        "unscannableFiles".to_string(),
        serde_json::Value::from(metadata.unscannable_files.len()),
    );
    properties.insert(
        "suppressedByBaseline".to_string(),
        serde_json::Value::from(metadata.suppressed_by_baseline),
    );

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "KeyWatch",
                    version: option_env!("CARGO_PKG_VERSION").map(|version| version.to_string()),
                    information_uri: "https://github.com/pixincreate/KeyWatch",
                    semantic_version: option_env!("CARGO_PKG_VERSION")
                        .map(|version| version.to_string()),
                },
            },
            results,
            properties,
        }],
    };

    serde_json::to_string_pretty(&log)
}
