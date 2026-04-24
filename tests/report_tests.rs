use key_watch::report::{create_report, ScanMetadata};

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
    use key_watch::report::Finding;

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
