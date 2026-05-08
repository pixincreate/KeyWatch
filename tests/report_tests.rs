use key_watch::report::{Finding, ScanMetadata, create_report, get_severity_counts};

#[test]
fn test_create_report() {
    let findings = vec![];
    let metadata = ScanMetadata {
        files_scanned: 5,
        total_lines: 100,
        excluded_files: vec![],
    };

    let report = create_report(findings, metadata, "0.5s".to_string())
        .expect("create_report should succeed");
    assert!(
        report.contains("\"status\": \"PASS\""),
        "Empty findings should be PASS"
    );
    assert!(
        report.contains("\"files_scanned\": 5"),
        "Should include files_scanned"
    );
    assert!(
        report.contains("\"scan_time\": \"0.5s\""),
        "Should include scan_time"
    );
}

#[test]
fn test_report_with_findings() {
    let findings = vec![Finding {
        file_path: "secret.txt".to_string(),
        line_number: 10,
        finding_type: "AWS Key".to_string(),
        severity: "HIGH".to_string(),
        matched_content: "AKIATESTKEY".to_string(),
        plugin_name: "AWSKeyDetector".to_string(),
    }];
    let metadata = ScanMetadata {
        files_scanned: 1,
        total_lines: 50,
        excluded_files: vec![],
    };

    let report = create_report(findings, metadata, "0.1s".to_string())
        .expect("create_report should succeed");
    assert!(
        report.contains("\"status\": \"FAIL\""),
        "Should report FAIL status"
    );
    assert!(report.contains("AWS Key"), "Should include finding type");
}

#[test]
fn test_create_report_includes_excluded_files_and_plugin_metadata() {
    let findings = vec![Finding {
        file_path: "secret.txt".to_string(),
        line_number: 7,
        finding_type: "API Token".to_string(),
        severity: "MEDIUM".to_string(),
        matched_content: "tok_test_123".to_string(),
        plugin_name: "TokenDetector".to_string(),
    }];
    let metadata = ScanMetadata {
        files_scanned: 2,
        total_lines: 80,
        excluded_files: vec!["ignored.log".to_string(), "vendor/secrets.txt".to_string()],
    };

    let report = create_report(findings, metadata, "1.2s".to_string())
        .expect("create_report should succeed");

    assert!(report.contains("\"excluded_files\""));
    assert!(report.contains("ignored.log"));
    assert!(report.contains("vendor/secrets.txt"));
    assert!(report.contains("\"plugin_name\": \"TokenDetector\""));
    assert!(report.contains("\"matched_content\": \"tok_test_123\""));
    assert!(report.contains("\"total_lines\": 80"));
}

#[test]
fn test_get_severity_counts_groups_high_medium_low() {
    let findings = vec![
        Finding {
            file_path: "a.txt".to_string(),
            line_number: 1,
            finding_type: "A".to_string(),
            severity: "HIGH".to_string(),
            matched_content: "a".to_string(),
            plugin_name: "DetectorA".to_string(),
        },
        Finding {
            file_path: "b.txt".to_string(),
            line_number: 2,
            finding_type: "B".to_string(),
            severity: "MEDIUM".to_string(),
            matched_content: "b".to_string(),
            plugin_name: "DetectorB".to_string(),
        },
        Finding {
            file_path: "c.txt".to_string(),
            line_number: 3,
            finding_type: "C".to_string(),
            severity: "LOW".to_string(),
            matched_content: "c".to_string(),
            plugin_name: "DetectorC".to_string(),
        },
        Finding {
            file_path: "d.txt".to_string(),
            line_number: 4,
            finding_type: "D".to_string(),
            severity: "HIGH".to_string(),
            matched_content: "d".to_string(),
            plugin_name: "DetectorD".to_string(),
        },
    ];

    let counts = get_severity_counts(&findings);

    assert_eq!(counts, (2, 1, 1));
}
