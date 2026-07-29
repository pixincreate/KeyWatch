use key_watch::baseline::{Baseline, BaselineEntry};
use key_watch::report::{Finding, Severity};
use std::fs;

fn make_finding(file: &str, line: usize, ftype: &str, content: &str, plugin: &str) -> Finding {
    Finding {
        file_path: file.to_string(),
        line_number: line,
        finding_type: ftype.to_string(),
        severity: Severity::High,
        matched_content: content.to_string(),
        plugin_name: plugin.to_string(),
    }
}

#[test]
fn test_baseline_filters_known_findings() {
    let known_finding = make_finding(
        "test.txt",
        5,
        "AWS Key",
        "AKIAIOSFODNN7EXAMPLE",
        "AWSAccessKeyDetector",
    );
    let baseline = Baseline::from_findings(std::slice::from_ref(&known_finding));

    let findings = vec![
        known_finding,
        make_finding(
            "other.txt",
            1,
            "API Key",
            "sk-abc",
            "GenericKeyValueDetector",
        ),
    ];

    let filtered = baseline.filter_findings(findings);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].file_path, "other.txt");
}

#[test]
fn test_baseline_allows_new_findings() {
    let baseline = Baseline::default();
    let findings = vec![make_finding(
        "test.txt",
        1,
        "API Key",
        "sk-abc",
        "GenericKeyValueDetector",
    )];
    let filtered = baseline.filter_findings(findings);
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_baseline_save_and_load() -> Result<(), String> {
    let temp_file = std::env::temp_dir().join("keywatch_test_baseline.json");
    let baseline = Baseline {
        version: "1.0".to_string(),
        entries: vec![BaselineEntry {
            file_path: "a.txt".to_string(),
            line_number: 1,
            finding_type: "X".to_string(),
            matched_content_hash: "hash_secret".to_string(),
            plugin_name: "D".to_string(),
        }],
    };

    baseline.save(&temp_file)?;
    let loaded = Baseline::load(&temp_file)?;
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].file_path, "a.txt");

    let _ = fs::remove_file(&temp_file);
    Ok(())
}

#[test]
fn test_baseline_from_findings() {
    let findings = vec![
        make_finding("f1.txt", 1, "A", "x", "D1"),
        make_finding("f2.txt", 2, "B", "y", "D2"),
    ];
    let baseline = Baseline::from_findings(&findings);
    assert_eq!(baseline.entries.len(), 2);
}

#[test]
fn test_baseline_update_merges_new_findings() {
    let mut baseline = Baseline::from_findings(&[make_finding("old.txt", 1, "X", "old", "D")]);
    let new_findings = vec![
        make_finding("old.txt", 1, "X", "old", "D"),
        make_finding("new.txt", 2, "Y", "new", "D2"),
    ];

    baseline.update_with_findings(&new_findings);

    assert_eq!(baseline.entries.len(), 2);
    assert!(baseline.entries.iter().any(|e| e.file_path == "old.txt"));
    assert!(baseline.entries.iter().any(|e| e.file_path == "new.txt"));
}

#[test]
fn test_baseline_update_preserves_existing() {
    let mut baseline =
        Baseline::from_findings(&[make_finding("existing.txt", 5, "API", "secret", "D")]);
    baseline.update_with_findings(&[]);

    assert_eq!(baseline.entries.len(), 1);
    assert_eq!(baseline.entries[0].file_path, "existing.txt");
}
