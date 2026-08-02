use std::fs;
use std::process::Command;

#[test]
fn test_scan_stdin_with_path_exits_two_with_validation_error() {
    let temp_dir = tempfile::tempdir().expect("Create test dir");
    fs::write(
        temp_dir.path().join("secret.txt"),
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
    )
    .expect("Write test file");

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(temp_dir.path())
        .arg("scan")
        .arg("secret.txt")
        .arg("--stdin")
        .output()
        .expect("Run key-watch");

    assert_eq!(
        output.status.code(),
        Some(2),
        "Should exit 2 for invalid stdin/path usage"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim(),
        "Error: Cannot specify both --stdin and paths"
    );
}
