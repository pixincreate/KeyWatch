use super::{Finding, ScanMetadata, Severity};
use serde::Serialize;
use std::collections::HashMap;

/// Generate a SARIF 2.1.0 report from findings.
pub fn create_sarif_report(
    findings: Vec<Finding>,
    _metadata: ScanMetadata,
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
        properties: HashMap<String, serde_json::Value>,
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
        semantic_version: Option<String>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifResult {
        rule_id: String,
        level: &'static str,
        message: SarifMessage,
        locations: Vec<SarifLocation>,
        properties: HashMap<String, serde_json::Value>,
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
            let uri = finding.file_path;
            let start_line = finding.line_number;

            let mut properties = HashMap::new();
            properties.insert(
                "precision".to_string(),
                serde_json::Value::String("very-high".to_string()),
            );
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
