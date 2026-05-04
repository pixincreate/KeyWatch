use std::env::temp_dir;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn unique_test_dir(name: &str) -> PathBuf {
    temp_dir().join(format!(
        "keywatch_{name}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ))
}

fn setup_scan_dir(name: &str, include_detectors: bool) -> PathBuf {
    let dir = unique_test_dir(name);
    fs::create_dir(&dir).expect("Create test dir");

    if include_detectors {
        let detectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("detectors.toml");
        fs::copy(detectors, dir.join("detectors.toml")).expect("Copy detectors.toml");
    }

    dir
}

#[test]
fn test_exit_code_on_secrets() {
    let test_dir = setup_scan_dir("exit_secrets", true);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").expect("Write test file");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("--file")
        .arg(&temp_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(1),
        "Should exit 1 when secrets are found"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exit_code_on_no_secrets() {
    let test_dir = setup_scan_dir("exit_no_secrets", true);
    let temp_file = test_dir.join("plain.txt");
    fs::write(&temp_file, "This is just plain text.").expect("Write test file");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("--file")
        .arg(&temp_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(0),
        "Should exit 0 when no secrets are found"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_runtime_errors_exit_with_code_two() {
    let test_dir = setup_scan_dir("exit_runtime_error", false);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").expect("Write test file");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("--file")
        .arg(&temp_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(status.code(), Some(2), "Should exit 2 on runtime errors");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exit_mode_always() {
    let test_dir = setup_scan_dir("exit_always", true);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").expect("Write test file");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("--file")
        .arg(&temp_file)
        .arg("--exit-mode")
        .arg("always")
        .status()
        .expect("Run key-watch");

    assert_eq!(status.code(), Some(0), "Should exit 0 in always mode");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exit_mode_critical_high_vs_low() {
    let high_dir = setup_scan_dir("exit_critical_high", true);
    let high_file = high_dir.join("secret.txt");
    fs::write(&high_file, "AKIAABCDEFGHIJKLMNOP").expect("Write HIGH severity");

    let high_status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&high_dir)
        .arg("--file")
        .arg(&high_file)
        .arg("--exit-mode")
        .arg("critical")
        .status()
        .expect("Run key-watch");

    assert_eq!(
        high_status.code(),
        Some(1),
        "Should exit 1 for HIGH severity findings"
    );

    let low_dir = setup_scan_dir("exit_critical_low", true);
    let low_file = low_dir.join("secret.txt");
    fs::write(&low_file, "user@example.com").expect("Write LOW severity");

    let low_status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&low_dir)
        .arg("--file")
        .arg(&low_file)
        .arg("--exit-mode")
        .arg("critical")
        .status()
        .expect("Run key-watch");

    assert_eq!(
        low_status.code(),
        Some(0),
        "Should exit 0 for non-HIGH findings in critical mode"
    );

    fs::remove_dir_all(high_dir).expect("Cleanup high dir");
    fs::remove_dir_all(low_dir).expect("Cleanup low dir");
}
