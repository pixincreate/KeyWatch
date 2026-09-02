use key_watch::cli::{ExitMode, OutputFormat, ScanArgs};
use key_watch::scanner::{ScannerError, run_scan};
use std::env::temp_dir;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();

    temp_dir().join(format!("keywatch_{name}_{stamp}_{}", std::process::id()))
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn init_git_repo(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("create repo dir: {error}"))?;

    let status = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git init: {error}"))?;
    if !status.success() {
        return Err("git init failed".to_string());
    }

    for (key, value) in [("user.email", "test@test.com"), ("user.name", "Test")] {
        let status = Command::new("git")
            .args(["config", key, value])
            .current_dir(path)
            .status()
            .map_err(|error| format!("git config {key}: {error}"))?;
        if !status.success() {
            return Err(format!("git config {key} failed"));
        }
    }

    Ok(())
}

fn commit_file(path: &Path, file_name: &str, contents: &str, message: &str) -> Result<(), String> {
    let file_path = path.join(file_name);
    fs::write(&file_path, contents).map_err(|error| format!("write file: {error}"))?;

    let status = Command::new("git")
        .args(["add", file_name])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git add: {error}"))?;
    if !status.success() {
        return Err("git add failed".to_string());
    }

    // --no-verify keeps fixture commits hermetic on machines where a global
    // core.hooksPath installs a secret-scanning pre-commit hook; these tests
    // exercise git-history scanning, not hooks.
    let status = Command::new("git")
        .args(["commit", "-m", message, "--quiet", "--no-verify"])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git commit: {error}"))?;
    if !status.success() {
        return Err("git commit failed".to_string());
    }

    Ok(())
}

fn detectors_config_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("detectors.toml")
}

fn run_git_history_scan(current_dir: &Path, extra_args: &[&str]) -> Result<Output, String> {
    Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--git-history"])
        .args(extra_args)
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(current_dir)
        .output()
        .map_err(|error| format!("run key-watch scan --git-history: {error}"))
}

#[cfg(unix)]
fn symlink_file(original: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(original, link).map_err(|error| format!("create symlink: {error}"))
}

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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: Some("*.log".to_string()),
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (_findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
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
fn test_invalid_cli_exclude_pattern_returns_typed_error() {
    let options = ScanArgs {
        paths: vec![".".to_string()],
        stdin: false,
        git_history: false,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: Some("[".to_string()),
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let error = match run_scan(&options, None) {
        Ok(_) => panic!("invalid exclude should fail"),
        Err(error) => error,
    };

    match &error {
        ScannerError::InvalidExcludePattern { pattern, source: _ } => {
            assert_eq!(pattern, "[");
        }
        other_error => panic!("expected invalid exclude pattern error, got {other_error:?}"),
    }
    assert!(
        error
            .to_string()
            .starts_with("Invalid exclude pattern '[': "),
        "legacy display prefix changed: {error}"
    );
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
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

#[cfg(unix)]
#[test]
fn test_explicit_symlink_path_is_skipped() -> Result<(), String> {
    let test_dir = unique_temp_dir("explicit_symlink_skip");
    let outside_file = test_dir.join("outside-secret.txt");
    let link_path = test_dir.join("linked-secret.txt");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).map_err(|error| format!("create test dir: {error}"))?;
    fs::write(&outside_file, "AWS Key: AKIAABCDEFGHIJKLMNOP\n")
        .map_err(|error| format!("write outside secret: {error}"))?;
    symlink_file(&outside_file, &link_path)?;

    let options = ScanArgs {
        paths: vec![
            link_path
                .to_str()
                .ok_or("link path should be utf-8")?
                .to_string(),
        ],
        stdin: false,
        git_history: false,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");

    assert!(findings.is_empty(), "Symlink target should not be scanned");
    assert_eq!(
        metadata.files_scanned, 0,
        "Symlink should not count as scanned"
    );

    fs::remove_dir_all(&test_dir).map_err(|error| format!("cleanup: {error}"))?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_recursive_symlink_path_is_skipped() -> Result<(), String> {
    let test_dir = unique_temp_dir("recursive_symlink_skip");
    let outside_file = test_dir.join("outside-secret.txt");
    let scan_root = test_dir.join("scan-root");
    let link_path = scan_root.join("linked-secret.txt");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&scan_root).map_err(|error| format!("create scan root: {error}"))?;
    fs::write(&outside_file, "AWS Key: AKIAABCDEFGHIJKLMNOP\n")
        .map_err(|error| format!("write outside secret: {error}"))?;
    symlink_file(&outside_file, &link_path)?;

    let options = ScanArgs {
        paths: vec![
            scan_root
                .to_str()
                .ok_or("scan root should be utf-8")?
                .to_string(),
        ],
        stdin: false,
        git_history: false,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");

    assert!(
        findings.is_empty(),
        "Recursive symlink target should not be scanned"
    );
    assert_eq!(
        metadata.files_scanned, 0,
        "Recursive symlink should not count as scanned"
    );

    fs::remove_dir_all(&test_dir).map_err(|error| format!("cleanup: {error}"))?;
    Ok(())
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
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
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: Some("subdir/secret.txt".to_string()),
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");

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
    fs::write(&test_file, content)
        .map_err(|error| format!("Unable to write test file: {error}"))?;

    let path_str = test_file.to_string_lossy().to_string();

    let options = ScanArgs {
        paths: vec![path_str],
        stdin: false,
        git_history: false,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");

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

    fs::remove_file(test_file).map_err(|error| format!("Cleanup failed: {error}"))?;
    Ok(())
}

#[test]
fn test_stdin_args_validation() {
    let options = ScanArgs {
        paths: vec![],
        stdin: true,
        git_history: false,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
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
        .map_err(|error| format!("spawn key-watch --stdin: {error}"))?;

    let mut stdin = child.stdin.take().ok_or("Failed to capture stdin")?;
    stdin
        .write_all(b"AWS Key: AKIAABCDEFGHIJKLMNOP\npassword = 'secret123'\n")
        .map_err(|error| format!("write to stdin: {error}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let combined = format!("{}{}", stdout, stderr);
    assert!(
        // AWS key + password. The Base64Detector no longer double-counts the
        // AWS key itself: its entropy (~4.0) is below the 4.2 threshold.
        combined.contains("2 potential secret(s)"),
        "Should detect 2 secrets from stdin input\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    Ok(())
}

#[test]
fn test_git_history_args_validation_allows_zero_or_one_path() {
    let zero_paths = ScanArgs {
        paths: vec![],
        stdin: false,
        git_history: true,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };
    let one_path = ScanArgs {
        paths: vec!["/tmp/requested-root".to_string()],
        stdin: false,
        git_history: true,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };
    let two_paths = ScanArgs {
        paths: vec![
            "/tmp/requested-root".to_string(),
            "/tmp/other-root".to_string(),
        ],
        stdin: false,
        git_history: true,
        staged: false,
        output: None,
        verbose: false,
        show_secrets: false,
        exclude: None,
        exit_mode: ExitMode::Strict,
        baseline: None,
        update_baseline: false,
        no_baseline_discovery: true,
        config: None,
        no_config_discovery: false,
        format: OutputFormat::Json,
    };

    assert!(zero_paths.validate().is_ok());
    assert!(one_path.validate().is_ok());
    assert!(two_paths.validate().is_err());
}

#[test]
fn test_git_history_defaults_to_current_directory_when_no_path_is_provided() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("git_history_default_cwd");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "secrets.txt",
        "AWS Key: AKIAABCDEFGHIJKLMNOP\n",
        "initial",
    )?;

    let output = run_git_history_scan(&repo_dir, &[])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "default cwd git history scan should report findings\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(combined.contains("potential secret(s) detected"));

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_git_history_scans_requested_root_from_a_different_current_directory() -> Result<(), String>
{
    if !git_available() {
        return Ok(());
    }

    let parent_dir = unique_temp_dir("git_history_requested_root_parent");
    let requested_root = parent_dir.join("requested-repo");
    let _ = fs::remove_dir_all(&parent_dir);
    init_git_repo(&requested_root)?;
    commit_file(
        &requested_root,
        "secrets.txt",
        "AWS Key: AKIAQRSTUVWXYZABCDEF\n",
        "initial",
    )?;

    let output = run_git_history_scan(&parent_dir, &[requested_root.to_str().unwrap()])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "explicit git root scan should report findings\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(combined.contains("potential secret(s) detected"));

    let _ = fs::remove_dir_all(&parent_dir);
    Ok(())
}

#[test]
fn test_git_history_does_not_execute_textconv_helpers() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("git_history_no_textconv");
    let marker_path = repo_dir.join("textconv-helper-ran");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;

    let helper = format!(
        "sh -c 'printf textconv-ran > \"{}\"; cat \"$1\"' -",
        marker_path.display()
    );
    let status = Command::new("git")
        .env("GIT_MASTER", "1")
        .args(["config", "diff.keywatchmarker.textconv", &helper])
        .current_dir(&repo_dir)
        .status()
        .map_err(|error| format!("git config textconv: {error}"))?;
    if !status.success() {
        return Err("git config textconv failed".to_string());
    }

    commit_file(
        &repo_dir,
        ".gitattributes",
        "*.kw diff=keywatchmarker\n",
        "attrs",
    )?;
    commit_file(&repo_dir, "sample.kw", "ordinary text\n", "sample")?;

    let _output = run_git_history_scan(&repo_dir, &[])?;
    assert!(
        !marker_path.exists(),
        "git history scan must not execute configured textconv helpers"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

fn run_staged_scan(current_dir: &Path, extra_args: &[&str]) -> Result<Output, String> {
    Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged"])
        .args(extra_args)
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(current_dir)
        .output()
        .map_err(|error| format!("run key-watch scan --staged: {error}"))
}

fn stage_file(path: &Path, file_name: &str, contents: &str) -> Result<(), String> {
    let file_path = path.join(file_name);
    fs::write(&file_path, contents).map_err(|error| format!("write {file_name}: {error}"))?;

    let status = Command::new("git")
        .args(["add", file_name])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git add: {error}"))?;
    if !status.success() {
        return Err("git add failed".to_string());
    }

    Ok(())
}

#[test]
fn test_staged_scan_ignores_findings_on_unchanged_lines() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("staged_unchanged_lines");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "secrets.txt",
        "AWS Key: AKIAABCDEFGHIJKLMNOP\n",
        "initial",
    )?;
    stage_file(
        &repo_dir,
        "secrets.txt",
        "AWS Key: AKIAABCDEFGHIJKLMNOP\nplain documentation line\n",
    )?;

    let output = run_staged_scan(&repo_dir, &[])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "pre-existing secret on an unchanged line must not block\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_ignores_deletion_only_changes() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("staged_deletion_only");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "secrets.txt",
        "keep this line\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
        "initial",
    )?;
    stage_file(&repo_dir, "secrets.txt", "keep this line\n")?;

    let output = run_staged_scan(&repo_dir, &[])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "deletion-only staged change must not block\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_reports_added_secret_with_real_path_and_line() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("staged_added_secret");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "config.txt", "line one\nline two\n", "initial")?;
    stage_file(
        &repo_dir,
        "config.txt",
        "line one\nline two\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let output = run_staged_scan(&repo_dir, &["--verbose"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "a staged secret must block\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("\"file_path\": \"config.txt\""),
        "findings must carry the real file path, not <stdin>\nstdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("\"line_number\": 3"),
        "findings must carry the post-image line number\nstdout:\n{}",
        stdout
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_respects_exclude_patterns() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("staged_exclude");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "fixture.snap", "clean\n", "initial")?;
    stage_file(
        &repo_dir,
        "fixture.snap",
        "clean\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let output = run_staged_scan(&repo_dir, &["--exclude", "*.snap"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "excluded staged paths must not be scanned\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_composes_with_baseline() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("staged_baseline");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "config.txt", "line one\n", "initial")?;
    stage_file(
        &repo_dir,
        "config.txt",
        "line one\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let update = run_staged_scan(
        &repo_dir,
        &["--baseline", "baseline.json", "--update-baseline"],
    )?;
    assert!(
        matches!(update.status.code(), Some(0)),
        "baseline update should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );

    let output = run_staged_scan(&repo_dir, &["--baseline", "baseline.json"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "baselined staged findings must be suppressed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_baseline_file_itself_is_never_scanned() {
    let dir = unique_temp_dir("baseline_self_exclusion");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    fs::write(
        dir.join("secrets.txt"),
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    )
    .expect("write secret file");

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "."])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&dir)
            .output()
            .expect("run key-watch")
    };

    let update = run(&["--baseline", "baseline.json", "--update-baseline"]);
    assert!(update.status.success(), "baseline update should succeed");

    // Two consecutive baselined scans must be clean and must not grow the
    // baseline by re-scanning the baseline file's own hash strings.
    let first = run(&["--baseline", "baseline.json"]);
    let size_before = fs::metadata(dir.join("baseline.json")).unwrap().len();
    let second_update = run(&["--baseline", "baseline.json", "--update-baseline"]);
    assert!(second_update.status.success());
    let size_after = fs::metadata(dir.join("baseline.json")).unwrap().len();

    assert!(
        String::from_utf8_lossy(&first.stdout).contains("No secrets found."),
        "baselined findings must be suppressed, got:\n{}",
        String::from_utf8_lossy(&first.stdout)
    );
    assert_eq!(
        size_before, size_after,
        "re-updating the baseline must not ingest the baseline file itself"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_baseline_auto_discovered_from_repo_root() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("baseline_auto_discovery");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::create_dir_all(repo_dir.join("nested")).map_err(|e| e.to_string())?;
    fs::write(
        repo_dir.join("nested/config.txt"),
        "AWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    // No baseline anywhere: --update-baseline creates the conventional file.
    let update = run(&["scan", ".", "--update-baseline"]);
    assert!(
        update.status.success(),
        "default-name update should succeed"
    );
    assert!(
        repo_dir.join(".keywatch-baseline.json").exists(),
        "update should create .keywatch-baseline.json"
    );

    // A nested scan discovers the repo-root baseline and comes back clean.
    let scan = run(&["scan", "nested/config.txt"]);
    assert!(
        String::from_utf8_lossy(&scan.stdout).contains("No secrets found."),
        "discovered baseline should suppress known findings, got:\n{}",
        String::from_utf8_lossy(&scan.stdout)
    );

    // Discovery can be turned off.
    let no_discovery = run(&["scan", "nested/config.txt", "--no-baseline-discovery"]);
    assert_eq!(
        no_discovery.status.code(),
        Some(1),
        "--no-baseline-discovery must ignore the repo baseline"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_uses_discovered_baseline() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    let repo_dir = unique_temp_dir("staged_auto_baseline");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "config.txt", "clean line\n", "initial")?;
    stage_file(
        &repo_dir,
        "config.txt",
        "clean line\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    let update = run(&["scan", "--staged", "--update-baseline"]);
    assert!(
        update.status.success(),
        "staged baseline update should succeed"
    );

    // The hook's exact invocation now picks the baseline up automatically.
    let staged = run(&["scan", "--staged"]);
    assert!(
        matches!(staged.status.code(), Some(0)),
        "staged scan should discover the repo baseline\nstdout:\n{}",
        String::from_utf8_lossy(&staged.stdout)
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_discovered_baseline_file_is_never_scanned() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    // A discovered baseline resolves to an absolute path while scanned files
    // are relative, so self-exclusion must compare canonical paths.
    let repo_dir = unique_temp_dir("discovered_baseline_self_scan");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("secrets.txt"),
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "."])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&["--update-baseline"]).status.success());
    let size_before = fs::metadata(repo_dir.join(".keywatch-baseline.json"))
        .map_err(|e| e.to_string())?
        .len();

    let rescan = run(&[]);
    assert!(
        String::from_utf8_lossy(&rescan.stdout).contains("No secrets found."),
        "scanning the tree must not re-flag the discovered baseline's own hashes, got:\n{}",
        String::from_utf8_lossy(&rescan.stdout)
    );

    assert!(run(&["--update-baseline"]).status.success());
    let size_after = fs::metadata(repo_dir.join(".keywatch-baseline.json"))
        .map_err(|e| e.to_string())?
        .len();
    assert_eq!(
        size_before, size_after,
        "re-updating a discovered baseline must not ingest the baseline itself"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_skips_the_baseline_file() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    // Committing a baseline must not trip the hook: its stored hashes are
    // added lines in the staged diff and would otherwise be flagged.
    let repo_dir = unique_temp_dir("staged_skips_baseline");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("secrets.txt"),
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(args)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&["scan", ".", "--update-baseline"]).status.success());

    let status = Command::new("git")
        .args(["add", "secrets.txt", ".keywatch-baseline.json"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success(), "git add should succeed");

    let staged = run(&["scan", "--staged"]);
    assert!(
        matches!(staged.status.code(), Some(0)),
        "staging the baseline must not fail the hook\nstdout:\n{}",
        String::from_utf8_lossy(&staged.stdout)
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_repo_detectors_toml_cannot_disable_hook_scan() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    // A repository that ships its own detectors.toml replaces the detector
    // set. The hook runs with --no-config-discovery precisely so a scanned
    // repository cannot switch off detection for everyone who clones it.
    let repo_dir = unique_temp_dir("hostile_detectors_toml");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("detectors.toml"),
        "[[detectors]]\nname = \"Noop\"\npattern = \"\\\\bqqqzzz1234\\\\b\"\n\
         finding_type = \"Noop\"\nseverity = \"LOW\"\n",
    )
    .map_err(|e| e.to_string())?;
    stage_file(
        &repo_dir,
        "leak.txt",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )?;
    let status = Command::new("git")
        .args(["add", "detectors.toml"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success());

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "--staged", "--no-baseline-discovery"])
            .args(extra)
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert_eq!(
        run(&["--no-config-discovery"]).status.code(),
        Some(1),
        "with built-in detectors the staged secret must still be reported"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_reads_blobs_git_renders_as_binary() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    // `*.env -diff` makes git emit only "Binary files ... differ", so the
    // added lines never appear in the diff. The scan must read the staged
    // blob instead of reporting the file as clean.
    let repo_dir = unique_temp_dir("staged_undiffable_blob");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(repo_dir.join(".gitattributes"), "*.env -diff\n").map_err(|e| e.to_string())?;
    stage_file(
        &repo_dir,
        "secrets.env",
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged", "--no-baseline-discovery", "--verbose"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(&repo_dir)
        .output()
        .expect("run key-watch");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(1),
        "a '-diff' gitattribute must not hide a staged secret\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("\"file_path\": \"secrets.env\""),
        "the finding must be attributed to the real path\nstdout:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_baseline_suppression_is_reported() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    // A committed baseline is repo-controlled data that silently removes
    // findings; the count must be visible so suppression cannot hide.
    let repo_dir = unique_temp_dir("baseline_suppression_visible");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("secrets.txt"),
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "."])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&["--update-baseline"]).status.success());
    let scan = run(&[]);
    let stdout = String::from_utf8_lossy(&scan.stdout);

    assert!(
        stdout.contains("Suppressed") && stdout.contains("finding(s)"),
        "the suppressed count must be printed, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_git_history_attributes_real_paths_and_honours_excludes() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    // History findings used to be keyed under a synthetic "<git-history>"
    // path, which no baseline entry could match, and this mode ignored
    // --exclude entirely.
    let repo_dir = unique_temp_dir("git_history_paths");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "leak.txt",
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        "add",
    )?;

    let verbose = run_git_history_scan(&repo_dir, &["--verbose", "--no-baseline-discovery"])?;
    let stdout = String::from_utf8_lossy(&verbose.stdout);
    assert!(
        stdout.contains("\"file_path\": \"leak.txt\""),
        "history findings must carry the real path, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("<git-history>"),
        "the synthetic path must be gone, got:\n{stdout}"
    );

    let excluded = run_git_history_scan(
        &repo_dir,
        &["--exclude", "leak.txt", "--no-baseline-discovery"],
    )?;
    assert_eq!(
        excluded.status.code(),
        Some(0),
        "--exclude must apply to git-history scans"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_survives_diff_relative_from_subdirectory() -> Result<(), String> {
    if !git_available() {
        return Ok(());
    }

    // diff.relative makes git emit cwd-relative paths and drop changes
    // outside the cwd, which silently hid staged secrets.
    let repo_dir = unique_temp_dir("staged_diff_relative");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::create_dir_all(repo_dir.join("sub")).map_err(|e| e.to_string())?;
    fs::write(repo_dir.join("sub/keep.txt"), "clean\n").map_err(|e| e.to_string())?;
    commit_file(&repo_dir, "root.txt", "clean\n", "init")?;
    let status = Command::new("git")
        .args(["config", "diff.relative", "true"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success());
    stage_file(
        &repo_dir,
        "root.txt",
        "clean\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged", "--no-baseline-discovery"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(repo_dir.join("sub"))
        .output()
        .expect("run key-watch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "diff.relative must not hide a staged secret outside the cwd"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}
