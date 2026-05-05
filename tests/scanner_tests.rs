use key_watch::cli::CliOptions;
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![],
        dir: Some(test_dir.to_str().unwrap().to_string()),
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![],
        dir: Some(test_dir.to_str().unwrap().to_string()),
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: Some("*.log".to_string()),
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![],
        dir: Some(test_dir.to_str().unwrap().to_string()),
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![temp_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(findings.is_empty(), "Should gracefully handle binary files");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_multiple_files_scan() {
    use key_watch::cli::CliOptions;
    use key_watch::scanner::run_scan;
    use std::env::temp_dir;
    use std::fs;

    let temp_dir = temp_dir();
    let test_file1 = temp_dir.join("keywatch_multi_test1.txt");
    let test_file2 = temp_dir.join("keywatch_multi_test2.txt");

    fs::write(&test_file1, "AWS_KEY=AKIATESTMULTI123").expect("Write test file 1");
    fs::write(&test_file2, "password=secretpassword123").expect("Write test file 2");

    let options = CliOptions {
        file: vec![
            test_file1.to_str().unwrap().to_string(),
            test_file2.to_str().unwrap().to_string(),
        ],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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
fn test_detect_aadhaar() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_aadhaar_test.txt");

    let content = "My Aadhaar: 1234-5678-9012\nBackup: 1234 5678 9012\nNo space: 123456789012";
    fs::write(&test_file, content).expect("Write test file");

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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

    let options = CliOptions {
        file: vec![test_file.to_str().unwrap().to_string()],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
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
