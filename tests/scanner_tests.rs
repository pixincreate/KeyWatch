use key_watch::cli::{ExitMode, ScanArgs};
use key_watch::scanner::run_scan;
use std::env::temp_dir;
use std::fs;

#[test]
fn test_find_secrets_in_file() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_multiple_secrets.txt");

    let content = "\
AWS Key: AKIAABCDEFGHIJKLMNOP\n\
password = 'mySecretPassword'\n\
email = user@example.com\n\
Firebase: AIzaSyC93k4n4BxvV_XYZ1234567890abcdefghijk\n\
SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n\
sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX\n\
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(!findings.is_empty(), "Should find secrets");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_find_api_tokens() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_api_tokens.txt");

    let content = "\
GitHub: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH\n\
Slack: xoxb-abcdefghijklmnop-qrstuvwxyz-123456789012\n\
Stripe: sk_test_51ABCDEF12345678901234567890\n\
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(!findings.is_empty(), "Should find API tokens");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_find_cloud_credentials() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_cloud.txt");

    let content = "\
AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n\
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
GCP_API_KEY=AIzaSyC93k4n4BxvV_XYZ1234567890abcdefghijk\n\
AZURE_STORAGE=DefaultEndpointsProtocol=https;AccountName=examplestore;
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(!findings.is_empty(), "Should find cloud credentials");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_find_private_key() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_private_key.txt");

    let content = "\
-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCxoe3Fy7N9i+Kj\n\
-----END RSA PRIVATE KEY-----\n\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1ldi0xLjAAABgQDQD2FGB3V2t4=\n\
-----END OPENSSH PRIVATE KEY-----\n\
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(!findings.is_empty(), "Should find private keys");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_multiple_detections_in_line() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_multi.txt");

    let content = "password=secret email=user@example.com key=AKIATESTKEY123";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(
        findings.len() >= 2,
        "Should find multiple secrets on one line"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_directory_scan_with_exclusions() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_test_dir_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");

    fs::write(test_dir.join("secret1.txt"), "AKIATESTKEY123").expect("Write file1");
    fs::write(test_dir.join("secret2.txt"), "password=secret").expect("Write file2");
    fs::create_dir_all(test_dir.join(".git")).expect("Create .git dir");
    fs::write(test_dir.join(".git/secret.txt"), "SHOULD_NOT_FIND").expect("Write git file");

    let options = ScanArgs {
        paths: vec![test_dir.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options).expect("run_scan should succeed");
    assert_eq!(
        metadata.files_scanned, 2,
        "Should scan 2 files (.git excluded)"
    );
    assert!(!findings.is_empty(), "Should find secrets");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exclude_pattern_filtering() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_exclude_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");

    fs::write(test_dir.join("secret.txt"), "password=secret123").expect("Write secret");
    fs::write(test_dir.join("debug.log"), "password=debug123").expect("Write log");

    let options = ScanArgs {
        paths: vec![test_dir.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: Some("*.log".to_string()),
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (_findings, metadata) = run_scan(&options).expect("run_scan should succeed");
    assert!(
        metadata
            .excluded_files
            .iter()
            .any(|f| f.contains("debug.log")),
        "Should exclude *.log"
    );
    assert_eq!(metadata.files_scanned, 1, "Should skip excluded files");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_dot_github_directory_is_scanned() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_dotgithub_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");
    fs::create_dir_all(test_dir.join(".github")).expect("Create .github dir");
    fs::write(test_dir.join(".github/workflow.txt"), "password=secret123").expect("Write file");

    let options = ScanArgs {
        paths: vec![test_dir.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options).expect("run_scan should succeed");
    assert_eq!(metadata.files_scanned, 1, "Should scan .github files");
    assert!(!findings.is_empty(), "Should find secrets inside .github");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_scan_no_secrets() {
    let temp_file = temp_dir().join("key_watch_no_secret.txt");
    let content = "This is a plain text file.\nThere is nothing secret here.";
    fs::write(&temp_file, content).expect("Unable to write no-secret file");

    let options = ScanArgs {
        paths: vec![temp_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(findings.is_empty(), "Should not find secrets in plain text");

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_non_utf8_file_handling() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_binary.bin");

    let content: Vec<u8> = vec![0x80, 0x81, 0x82, 0xff, 0xfe];
    fs::write(&test_file, content).expect("Unable to write binary test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(findings.is_empty(), "Should gracefully handle binary files");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_multiple_files_scan() {
    let temp_dir = temp_dir();
    let test_file1 = temp_dir.join("keywatch_multi_test1.txt");
    let test_file2 = temp_dir.join("keywatch_multi_test2.txt");

    fs::write(&test_file1, "AWS_KEY=AKIATESTMULTI123").expect("Write test file 1");
    fs::write(&test_file2, "password=secretpassword123").expect("Write test file 2");

    let options = ScanArgs {
        paths: vec![
            test_file1.to_str().unwrap().to_string(),
            test_file2.to_str().unwrap().to_string(),
        ],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options).expect("run_scan should succeed");
    assert!(
        !findings.is_empty(),
        "Should find secrets in multiple files"
    );
    assert_eq!(metadata.files_scanned, 2, "Should scan 2 files");

    fs::remove_file(test_file1).expect("Cleanup");
    fs::remove_file(test_file2).expect("Cleanup");
}

#[test]
fn test_duplicate_paths_are_scanned_once() {
    let temp_file = temp_dir().join("key_watch_duplicate_path.txt");
    fs::write(&temp_file, "password=duplicate-secret").expect("Write test file");

    let options = ScanArgs {
        paths: vec![
            temp_file.to_str().unwrap().to_string(),
            temp_file.to_str().unwrap().to_string(),
        ],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options).expect("run_scan should succeed");
    assert_eq!(
        metadata.files_scanned, 1,
        "Duplicate paths should be deduped"
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.file_path == temp_file.to_str().unwrap()),
        "Duplicate paths should only report findings for the deduped file"
    );

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_mixed_file_and_directory_paths_are_scanned_once() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_mixed_inputs_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");

    let direct_file = test_dir.join("secret.txt");
    fs::write(&direct_file, "password=mixed-secret").expect("Write test file");

    let options = ScanArgs {
        paths: vec![
            direct_file.to_str().unwrap().to_string(),
            test_dir.to_str().unwrap().to_string(),
        ],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options).expect("run_scan should succeed");
    assert_eq!(
        metadata.files_scanned, 1,
        "File should only be scanned once"
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.file_path == direct_file.to_str().unwrap()),
        "Mixed file/directory inputs should only report findings for the single deduped file"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_nonexistent_paths_are_ignored_without_counting_as_scanned() {
    let missing_path = temp_dir().join(format!(
        "keywatch_missing_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));

    let options = ScanArgs {
        paths: vec![missing_path.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options).expect("run_scan should succeed");
    assert!(
        findings.is_empty(),
        "Missing paths should not produce findings"
    );
    assert_eq!(
        metadata.files_scanned, 0,
        "Missing paths should not be counted as scanned"
    );
    assert!(
        metadata.excluded_files.is_empty(),
        "Missing paths should not be marked excluded"
    );
}

#[test]
fn test_detect_aadhaar() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_aadhaar_test.txt");

    let content = "My Aadhaar: 1234-5678-9012\nBackup: 1234 5678 9012\nNo space: 123456789012";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    let aadhaar_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "Aadhaar Card Number")
        .collect();
    assert!(
        !aadhaar_findings.is_empty(),
        "Should detect Aadhaar numbers"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_detect_voter_id() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_voter_id_test.txt");

    let content = "Voter ID: ABC1234567\nAnother: XYZ9876543";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    let voter_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "Voter ID (EPIC)")
        .collect();
    assert!(!voter_findings.is_empty(), "Should detect Voter ID numbers");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_detect_pan_card() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_pan_test.txt");

    let content = "PAN: ABCDE1234F\nBackup PAN: PQRST5678G";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    let pan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "PAN Card Number")
        .collect();
    assert!(!pan_findings.is_empty(), "Should detect PAN card numbers");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_detect_abha() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_abha_test.txt");

    let content = "ABHA: 1234-5678-9012-34\nMy Health ID: 9876-5432-1098-76";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    let abha_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "ABHA Health ID")
        .collect();
    assert!(!abha_findings.is_empty(), "Should detect ABHA health IDs");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_multiple_indian_ids() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_indian_ids.txt");

    let content =
        "Aadhaar: 9999-8888-7777\nVoter ID: ABC1234567\nPAN: XYZZU1234A\nABHA: 1111-2222-3333-44";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    let finding_types: Vec<_> = findings.iter().map(|f| f.finding_type.clone()).collect();

    assert!(
        finding_types.contains(&"Aadhaar Card Number".to_string()),
        "Should detect Aadhaar"
    );
    assert!(
        finding_types.contains(&"Voter ID (EPIC)".to_string()),
        "Should detect Voter ID"
    );
    assert!(
        finding_types.contains(&"PAN Card Number".to_string()),
        "Should detect PAN"
    );
    assert!(
        finding_types.contains(&"ABHA Health ID".to_string()),
        "Should detect ABHA"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_overlapping_scan_roots_with_exclusions() {
    let temp_dir = temp_dir();
    let root1 = temp_dir.join(format!(
        "keywatch_overlapping_1_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&root1).expect("Create test directory 1");

    let root2 = root1.join("subdir");
    fs::create_dir(&root2).expect("Create test directory 2");

    let test_file = root2.join("secret.txt");
    fs::write(&test_file, "password=secret123").expect("Write test file");

    let options = ScanArgs {
        paths: vec![
            root2.to_str().unwrap().to_string(), // Root 2 comes first to try to mess up order
            root1.to_str().unwrap().to_string(),
        ],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: Some("subdir/secret.txt".to_string()),
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options).expect("run_scan should succeed");

    assert!(
        metadata
            .excluded_files
            .iter()
            .any(|f| f.contains("secret.txt")),
        "File should be excluded despite overlapping roots"
    );
    assert!(
        findings.is_empty(),
        "No findings should be present because the file was excluded"
    );

    fs::remove_dir_all(root1).expect("Cleanup");
}

#[test]
fn test_inline_suppression_ignores_marked_lines() -> Result<(), String> {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_inline_suppress.txt");

    let content = "\
AWS Key: AKIAABCDEFGHIJKLMNOP # keywatch:ignore\npassword = 'mySecretPassword'\nemail = user@example.com // keywatch:ignore\nFirebase: AIzaSy012345678901234567890123456789012\n";
    fs::write(&test_file, content).map_err(|e| format!("Unable to write test file: {}", e))?;

    let path_str = test_file.to_string_lossy().to_string();

    let options = ScanArgs {
        paths: vec![path_str],
        stdin: false,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, _) = run_scan(&options)?;

    let aws_suppressed = findings
        .iter()
        .any(|f| f.matched_content.contains("AKIAABCDEFGHIJKLMNOP"));
    let email_suppressed = findings
        .iter()
        .any(|f| f.matched_content.contains("user@example.com"));
    let firebase_found = findings.iter().any(|f| {
        f.matched_content
            .contains("AIzaSy012345678901234567890123456789012")
    });

    assert!(
        !aws_suppressed,
        "AWS key with # keywatch:ignore should be suppressed"
    );
    assert!(
        !email_suppressed,
        "Email with // keywatch:ignore should be suppressed"
    );
    assert!(
        firebase_found,
        "Firebase key without suppression should still be found"
    );

    fs::remove_file(test_file).map_err(|e| format!("Cleanup failed: {}", e))?;
    Ok(())
}

#[test]
fn test_stdin_args_validation() {
    let options = ScanArgs {
        paths: vec![],
        stdin: true,
        git_history: false,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    assert!(options.validate().is_ok());
}

#[test]
fn test_stdin_scanning_integration() -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin_path = env!("CARGO_BIN_EXE_key-watch");
    let mut child = Command::new(bin_path)
        .args(["scan", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn key-watch --stdin: {}", e))?;

    let mut stdin = child.stdin.take().ok_or("Failed to capture stdin")?;
    stdin
        .write_all(b"AWS Key: AKIAABCDEFGHIJKLMNOP\npassword = 'secret123'\n")
        .map_err(|e| format!("write to stdin: {}", e))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("wait: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("3 potential secret(s)"),
        "Should detect 3 secrets from stdin input\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    Ok(())
}

#[test]
fn test_git_history_scanning() -> Result<(), String> {
    use std::process::Command;

    // Skip if git is not available
    if Command::new("git").arg("--version").output().is_err() {
        return Ok(());
    }

    let temp_dir = std::env::temp_dir().join("keywatch_test_git_history");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).map_err(|e| format!("Create dir: {}", e))?;

    Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&temp_dir)
        .output()
        .map_err(|e| format!("git init: {}", e))?;

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(&temp_dir)
        .output()
        .map_err(|e| format!("git config: {}", e))?;

    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(&temp_dir)
        .output()
        .map_err(|e| format!("git config: {}", e))?;

    let secret_file = temp_dir.join("secrets.txt");
    fs::write(&secret_file, "AWS Key: AKIAABCDEFGHIJKLMNOP\n")
        .map_err(|e| format!("Write file: {}", e))?;

    Command::new("git")
        .args(["add", "."])
        .current_dir(&temp_dir)
        .output()
        .map_err(|e| format!("git add: {}", e))?;

    Command::new("git")
        .args(["commit", "-m", "initial", "--quiet"])
        .current_dir(&temp_dir)
        .output()
        .map_err(|e| format!("git commit: {}", e))?;

    let options = ScanArgs {
        paths: vec![],
        stdin: false,
        git_history: true,
        output: None,
        verbose: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
    };

    let (findings, metadata) = run_scan(&options)?;

    assert!(
        findings
            .iter()
            .any(|f| f.matched_content.contains("AKIAABCDEFGHIJKLMNOP")),
        "Should find AWS key in git history"
    );
    assert_eq!(metadata.files_scanned, 1);

    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}
