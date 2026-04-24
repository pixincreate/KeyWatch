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
        file: Some(test_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
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
        file: Some(test_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
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
        file: Some(test_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
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
        file: Some(test_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
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
        file: Some(test_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
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
        file: None,
        dir: Some(test_dir.to_str().unwrap().to_string()),
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
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
        file: None,
        dir: Some(test_dir.to_str().unwrap().to_string()),
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: Some("*.log".to_string()),
        install_hook: None,
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

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_scan_no_secrets() {
    let temp_file = temp_dir().join("key_watch_no_secret.txt");
    let content = "This is a plain text file.\nThere is nothing secret here.";
    fs::write(&temp_file, content).expect("Unable to write no-secret file");

    let options = CliOptions {
        file: Some(temp_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
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
        file: Some(test_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let (findings, _) = run_scan(&options).expect("run_scan should succeed");
    assert!(findings.is_empty(), "Should gracefully handle binary files");

    fs::remove_file(test_file).expect("Cleanup");
}
