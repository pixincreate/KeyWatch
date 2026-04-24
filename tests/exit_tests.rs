use key_watch::cli::CliOptions;
use key_watch::scanner::run_scan;
use std::env::temp_dir;
use std::fs;

#[test]
fn test_exit_code_on_secrets() {
    let temp_file = temp_dir().join("keywatch_exit_secrets.txt");
    fs::write(&temp_file, "AWS_KEY=AKIATESTKEY123").expect("Write test file");

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

    let (findings, _) = run_scan(&options).expect("Scan should succeed");
    assert!(!findings.is_empty(), "Should find secrets");

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_exit_code_on_no_secrets() {
    let temp_file = temp_dir().join("keywatch_exit_no_secrets.txt");
    fs::write(&temp_file, "This is just plain text.").expect("Write test file");

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

    let (findings, _) = run_scan(&options).expect("Scan should succeed");
    assert!(findings.is_empty(), "Should not find secrets");

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_severity_levels() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_severity.txt");

    let content = "\
AKIAABCDEFGHIJKLMNOP\n\
password=secret\n\
user@example.com\n\
";
    fs::write(&test_file, content).expect("Write test file");

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

    let (findings, _) = run_scan(&options).expect("Scan should succeed");
    assert!(
        !findings.is_empty(),
        "Should find secrets with different severities"
    );

    let high = findings.iter().filter(|f| f.severity == "HIGH").count();
    let low = findings.iter().filter(|f| f.severity == "LOW").count();
    assert!(high > 0, "Should have HIGH severity findings");
    assert!(low > 0, "Should have LOW severity findings");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_exit_mode_always() {
    let temp_file = temp_dir().join("keywatch_exit_always.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").expect("Write test file");

    let options = CliOptions {
        file: Some(temp_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        exit_mode: "always".to_string(),
        verify_integrity: false,
    };

    let (findings, _) = run_scan(&options).expect("Scan should succeed");
    assert!(!findings.is_empty(), "Should find secrets");

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_exit_mode_critical_high_vs_low() {
    let temp_file = temp_dir().join("keywatch_exit_critical.txt");

    fs::write(&temp_file, "AKIAABCDEFGHIJKLMNOP").expect("Write HIGH severity");

    let options_high = CliOptions {
        file: Some(temp_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        exit_mode: "critical".to_string(),
        verify_integrity: false,
    };

    let (findings, _) = run_scan(&options_high).expect("Scan should succeed");
    assert!(
        findings.iter().any(|f| f.severity == "HIGH"),
        "Should have HIGH severity"
    );

    fs::write(&temp_file, "user@example.com").expect("Write LOW severity");

    let options_low = CliOptions {
        file: Some(temp_file.to_str().unwrap().to_string()),
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        exit_mode: "critical".to_string(),
        verify_integrity: false,
    };

    let (findings_low, _) = run_scan(&options_low).expect("Scan should succeed");
    assert!(
        findings_low.iter().all(|f| f.severity != "HIGH"),
        "Should NOT have HIGH"
    );

    fs::remove_file(temp_file).expect("Cleanup");
}
