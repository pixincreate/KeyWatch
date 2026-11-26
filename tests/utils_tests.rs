use key_watch::utils::write_to_file;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_write_to_file() {
    let directory = tempdir().expect("create private output directory");
    let temp_file = directory.path().join("report.txt");
    let content = "Temporary content written to file.";
    let path_str = temp_file.to_str().unwrap();

    write_to_file(path_str, content).expect("Failed to write to file");
    let read_back = fs::read_to_string(path_str).expect("Failed to read back");
    assert_eq!(read_back, content, "Content should match");
}

#[test]
fn test_portable_config_loading() {
    use key_watch::detector::initialize_detectors;

    let detectors = initialize_detectors().expect("Should load detectors");
    assert!(!detectors.is_empty(), "Should load at least one detector");
}

#[test]
fn test_write_to_file_replaces_existing_output() {
    let directory = tempdir().expect("create private output directory");
    let output = directory.path().join("report.txt");
    fs::write(&output, "original content").unwrap();

    write_to_file(output.to_str().unwrap(), "replacement content").unwrap();
    assert_eq!(fs::read_to_string(output).unwrap(), "replacement content");
}

#[cfg(unix)]
#[test]
fn test_write_to_file_tightens_existing_permissions() {
    use std::os::unix::fs::PermissionsExt;

    // Atomic replacement must not preserve world-readable permissions.
    let directory = tempdir().expect("create private output directory");
    let temp_file = directory.path().join("report.txt");
    let path_str = temp_file.to_str().unwrap();
    fs::write(path_str, "old content").expect("create pre-existing file");
    let mut perms = fs::metadata(path_str).expect("stat file").permissions();
    perms.set_mode(0o644);
    fs::set_permissions(path_str, perms).expect("set 0644");

    write_to_file(path_str, "new content").expect("rewrite file");
    assert_eq!(fs::read_to_string(path_str).unwrap(), "new content");

    let mode = fs::metadata(path_str)
        .expect("stat file")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "rewritten reports must be readable only by their owner"
    );
}

#[cfg(unix)]
#[test]
fn test_write_to_file_rejects_world_writable_parent_without_changing_output() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("create output directory");
    let output = directory.path().join("report.txt");
    fs::write(&output, "original content").unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();

    let error = write_to_file(output.to_str().unwrap(), "replacement content").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read_to_string(output).unwrap(), "original content");
}

#[cfg(unix)]
#[test]
fn reports_remain_owner_readable_under_a_restrictive_umask() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let directory = tempdir().unwrap();
    let input = directory.path().join("ordinary.txt");
    fs::write(&input, "ordinary text\n").unwrap();
    for existing in [false, true] {
        let report = directory.path().join(format!("report-{existing}.json"));
        if existing {
            fs::write(&report, "original content").unwrap();
        }
        let output = Command::new("sh")
            .args(["-c", "umask 0777; exec \"$@\"", "keywatch-umask"])
            .arg(env!("CARGO_BIN_EXE_key-watch"))
            .args([
                "scan",
                "--no-config-discovery",
                "--no-baseline-discovery",
                "--output",
            ])
            .arg(&report)
            .arg(&input)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let content: serde_json::Value =
            serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
        assert_eq!(content["status"], "PASS");
    }
}
