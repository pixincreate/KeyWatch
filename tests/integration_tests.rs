use key_watch::cli::CliOptions;
use key_watch::report::{create_report, ScanMetadata};
use key_watch::scanner::run_scan;
use key_watch::utils::write_to_file;
use std::env::temp_dir;
use std::fs;

//
// Test the scanning on a single file that contains multiple secrets.
// It checks that the detectors pick up various patterns (e.g. AWS key, password, and email).
//
#[test]
fn test_find_secrets_in_file() {
    // Create a temporary file in the system temp directory.
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_temp_secret.txt");

    let content = "\
AKIAABCDEFGHIJKLMNOP\n\
password = 'mySecretPassword'\n\
email = \"user@example.com\"\n\
";
    fs::write(&test_file, content).expect("Unable to write test file");

    // Build CLI options to scan the file.
    let options = CliOptions {
        file: Some(test_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
    };

    // Run the scan.
    let (findings, metadata) = run_scan(&options);

    // Expect the AWS key detector, Password detector, and Email detector to match.
    assert!(
        findings
            .iter()
            .any(|f| f.finding_type.contains("AWS Access Key")),
        "Expected to find an AWS Access Key."
    );
    assert!(
        findings.iter().any(|f| f.finding_type.contains("Password")),
        "Expected to find a Password."
    );
    assert!(
        findings
            .iter()
            .any(|f| f.finding_type.contains("Email Address")),
        "Expected to find an Email Address."
    );

    // Check metadata: exactly one file scanned.
    assert_eq!(metadata.files_scanned, 1, "Should have scanned 1 file.");
    // Clean up.
    fs::remove_file(&test_file).expect("Unable to remove temporary file");
}

//
// Test recursive directory scanning. We create a temporary directory with multiple files,
// including a file inside a .git directory (which should be excluded).
//
#[test]
fn test_directory_scan_with_exclusions() {
    let base_temp_dir = temp_dir().join("key_watch_temp_dir");
    fs::create_dir_all(&base_temp_dir).expect("Unable to create temporary base directory");

    // Create two files that should be scanned.
    // Updated file1 now contains a valid AWS key that matches: 4 + 16 characters.
    let file1_path = base_temp_dir.join("file1.txt");
    let file2_path = base_temp_dir.join("file2.txt");

    let content1 = "AKIA1234567890123456\nSome harmless text";
    let content2 = "password = 'anotherSecret'\nMore text here";

    fs::write(&file1_path, content1).expect("Unable to write file1");
    fs::write(&file2_path, content2).expect("Unable to write file2");

    // Create a subdirectory named .git where files should be excluded.
    let excluded_dir = base_temp_dir.join(".git");
    fs::create_dir_all(&excluded_dir).expect("Unable to create .git directory");
    let excluded_file = excluded_dir.join("ignored.txt");
    fs::write(&excluded_file, "This file should be excluded")
        .expect("Unable to write excluded file");

    // Build CLI options: set the directory to scan.
    let options = CliOptions {
        file: None,
        dir: Some(base_temp_dir.to_str().unwrap().to_string()),
        output: None,
        verbose: false,
    };

    let (findings, metadata) = run_scan(&options);

    // We expect exactly 2 scanned files (excluding those under .git).
    assert_eq!(
        metadata.files_scanned, 2,
        "Should have scanned 2 files (excluding ones in .git)"
    );
    // Verify that some files were excluded.
    assert!(
        !metadata.excluded_files.is_empty(),
        "Expected some files to be excluded."
    );
    // Check that our expected findings are present.
    assert!(
        findings
            .iter()
            .any(|f| f.finding_type.contains("AWS Access Key")),
        "Expected to find an AWS Access Key in file1."
    );
    assert!(
        findings.iter().any(|f| f.finding_type.contains("Password")),
        "Expected to find a Password in file2."
    );

    // Cleanup the temporary directory and its contents.
    fs::remove_dir_all(&base_temp_dir).expect("Unable to remove temporary directory");
}

//
// Test the report creation functionality. The test constructs a report from an empty
// set of findings (which should yield a PASS status) and checks that the JSON has the proper content.
//
#[test]
fn test_create_report() {
    // Create an empty vector of findings.
    let findings: Vec<key_watch::report::Finding> = Vec::new();
    // Build fake metadata.
    let metadata = ScanMetadata {
        files_scanned: 1,
        total_lines: 10,
        excluded_files: vec!["ignored_file.txt".to_string()],
    };
    // Create the report.
    let report_json = create_report(findings, metadata, "0.1s".to_string());
    // Check that the report indicates PASS when there are no findings.
    assert!(
        report_json.contains("\"status\": \"PASS\""),
        "Report should show PASS status"
    );
    // Verify that metadata values are present.
    assert!(
        report_json.contains("\"files_scanned\": 1"),
        "Report should include files_scanned"
    );
    assert!(
        report_json.contains("\"scan_time\": \"0.1s\""),
        "Report should include scan_time"
    );
}

//
// Test the write_to_file utility function.
//
#[test]
fn test_write_to_file() {
    let temp_file_path = temp_dir().join("key_watch_test_output.txt");
    let content = "Temporary content written to file.";
    let path_str = temp_file_path.to_str().unwrap();

    write_to_file(path_str, content).expect("Failed to write to file");
    let read_back = fs::read_to_string(path_str).expect("Failed to read back from file");
    assert_eq!(
        read_back, content,
        "The written and read content should match"
    );

    // Clean up.
    fs::remove_file(temp_file_path).expect("Unable to remove temporary output file");
}

//
// Test scanning a file that does not contain any secrets.
// The resulting findings should be empty and the report should indicate a PASS status.
//
#[test]
fn test_scan_no_secrets() {
    let temp_file_path = temp_dir().join("key_watch_no_secret.txt");
    let content = "This is a plain text file.\nThere is nothing secret here.";
    fs::write(&temp_file_path, content).expect("Unable to write no-secret file");

    let options = CliOptions {
        file: Some(temp_file_path.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
    };

    let (findings, _metadata) = run_scan(&options);
    assert_eq!(
        findings.len(),
        0,
        "No findings should be detected in a clean file"
    );

    // Clean up.
    fs::remove_file(&temp_file_path).expect("Unable to remove no-secret file");
}

//
// Additional test: verify that scanning works with multiple lines and detects multiple occurrences per line.
//
#[test]
fn test_multiple_detections_in_line() {
    let temp_file_path = temp_dir().join("key_watch_multiple.txt");
    // This file contains two potential secrets on one line.
    let content = "AKIAABCDEFGHIJKLMNOP password = \"superSecret!\"";
    fs::write(&temp_file_path, content).expect("Unable to write multiple detection file");

    let options = CliOptions {
        file: Some(temp_file_path.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
    };

    let (findings, _metadata) = run_scan(&options);
    // We expect at least two findings from the single line.
    assert!(
        findings.len() >= 2,
        "Expected at least two findings (AWS key and Password) but got {}",
        findings.len()
    );
    // Check that both types are present.
    assert!(
        findings
            .iter()
            .any(|f| f.finding_type.contains("AWS Access Key")),
        "Expected to find an AWS Access Key in the line."
    );
    assert!(
        findings.iter().any(|f| f.finding_type.contains("Password")),
        "Expected to find a Password in the line."
    );

    // Clean up.
    fs::remove_file(&temp_file_path).expect("Unable to remove multiple detection file");
}
