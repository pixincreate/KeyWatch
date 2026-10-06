use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("Git is required for hardening tests");
    assert!(output.status.success(), "{output:?}");
}

fn repository() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--quiet"]);
    git(dir.path(), &["config", "user.name", "Fixture"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    dir
}

fn scan(repo: &Path, args: &[&str]) -> (Output, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(repo)
        .args([
            "scan",
            "--no-config-discovery",
            "--no-baseline-discovery",
            "--verbose",
        ])
        .args(args)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("expected JSON report: {output:?}"));
    (output, report)
}

#[test]
fn git_configuration_cannot_change_exclusion_paths_or_line_numbers() {
    let dir = repository();
    fs::write(
        dir.path().join("credentials.env"),
        "first\nsecond\nthird\nfourth\nfifth\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "Fixture"]);
    fs::write(
        dir.path().join("credentials.env"),
        "changed\nsecond\nthird\nfourth\nAWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["config", "diff.srcPrefix", "other/"]);
    git(dir.path(), &["config", "diff.dstPrefix", "vendor/"]);
    git(dir.path(), &["config", "diff.interHunkContext", "10"]);
    let (output, report) = scan(dir.path(), &["--staged", "--exclude", "vendor/**"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["plugin_name"] == "AWSKeyDetector"
                    && finding["file_path"] == "credentials.env"
                    && finding["line_number"] == 5
            })
    );
}

#[test]
fn incomplete_scans_never_report_pass_and_explicit_failure_overrides_severity_policy() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("binary.dat"), b"data\0data").unwrap();
    for mode in ["strict", "critical", "always"] {
        let (output, report) = scan(
            dir.path(),
            &[".", "--exit-mode", mode, "--fail-on-unscannable"],
        );
        assert_eq!(output.status.code(), Some(1), "{mode}");
        assert_eq!(report["status"], "INCOMPLETE");
        assert_eq!(report["coverage"], "INCOMPLETE");
        assert_eq!(report["finding_status"], "PASS");
    }
}

#[test]
fn shallow_history_is_disclosed_and_fails_closed_when_requested() {
    let dir = repository();
    fs::write(
        dir.path().join("credentials.env"),
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "Old fixture"]);
    fs::write(dir.path().join("credentials.env"), "clean\n").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "Clean fixture"]);
    let clone_parent = tempfile::tempdir().unwrap();
    let clone = clone_parent.path().join("shallow");
    git(
        clone_parent.path(),
        &[
            "clone",
            "--quiet",
            "--depth",
            "1",
            &format!("file://{}", dir.path().display()),
            clone.to_str().unwrap(),
        ],
    );
    let (output, report) = scan(
        &clone,
        &[
            "--git-history",
            "--fail-on-unscannable",
            "--exit-mode",
            "critical",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["coverage"], "INCOMPLETE");
    assert!(
        report["coverage_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("shallow"))
    );
}

#[test]
fn historical_text_marked_binary_is_scanned_from_its_committed_blob() {
    let dir = repository();
    fs::write(dir.path().join(".gitattributes"), "credentials.env -diff\n").unwrap();
    fs::write(
        dir.path().join("credentials.env"),
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "Secret fixture"]);
    fs::write(dir.path().join("credentials.env"), "clean\n").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "Clean fixture"]);
    let (output, report) = scan(dir.path(), &["--git-history", "--fail-on-unscannable"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["plugin_name"] == "AWSKeyDetector"
                    && finding["file_path"] == "credentials.env"
            })
    );
    assert_eq!(report["unscannable"]["count"], 0);
}

#[test]
fn incomplete_scan_does_not_replace_an_existing_baseline() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("binary.dat"), b"data\0data").unwrap();
    let baseline = dir.path().join("accepted.json");
    let original = b"{\"version\":\"1.0\",\"entries\":[]}";
    fs::write(&baseline, original).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(dir.path())
        .args([
            "scan",
            "binary.dat",
            "--baseline",
            baseline.to_str().unwrap(),
            "--no-config-discovery",
            "--update-baseline",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(baseline).unwrap(), original);
}

#[test]
fn input_limits_apply_to_files_and_staged_text_without_overflow() {
    let dir = repository();
    let content = format!(
        "{}AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
        "# ordinary\n".repeat(110_000)
    );
    fs::write(dir.path().join("large.env"), content).unwrap();
    git(dir.path(), &["add", "."]);
    for mode in [vec!["large.env"], vec!["--staged"]] {
        let mut args = mode;
        args.extend(["--max-file-size", "1", "--fail-on-unscannable"]);
        let (output, report) = scan(dir.path(), &args);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(report["coverage"], "INCOMPLETE");
        assert_eq!(report["unscannable"]["count"], 1);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(dir.path())
        .args([
            "scan",
            "large.env",
            "--no-config-discovery",
            "--max-file-size",
            "17592186044416",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("size"));
}

#[test]
fn cross_line_rules_and_line_anchors_do_not_depend_on_regex_spelling() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("input.txt"),
        format!(
            "ordinary\nBEGIN\n{}END\nINT_ABCDEFGHIJKLMNOPQRST\n",
            "ordinary\n".repeat(1100)
        ),
    )
    .unwrap();
    for (pattern, expected) in [
        (r"BEGIN\n(?:ordinary\n)*END", "BEGIN\n"),
        (r"BEGIN[\s\S]*?END", "BEGIN\n"),
        (r"(?s:BEGIN.*?END)", "BEGIN\n"),
        (r"^(?P<secret>INT_[A-Z]{20})$", "INT_ABCDEFGHIJKLMNOPQRST"),
        (r"(?i-s)^INT_[A-Z]{20}$", "INT_ABCDEFGHIJKLMNOPQRST"),
    ] {
        let config = dir.path().join("rule.toml");
        fs::write(&config, format!("[[rules]]\nname = 'CrossLineFixture'\nfinding_type = 'Fixture'\npattern = '{pattern}'\n")).unwrap();
        let (output, report) = scan(
            dir.path(),
            &[
                "input.txt",
                "--show-secrets",
                "--config",
                config.to_str().unwrap(),
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["plugin_name"] == "CrossLineFixture"
                        && finding["matched_content"]
                            .as_str()
                            .unwrap()
                            .starts_with(expected)
                }),
            "{pattern}"
        );
    }
}

#[test]
fn oversized_lines_fail_instead_of_truncating_and_reporting_clean() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("long.txt"), "x".repeat(1024 * 1024 + 1)).unwrap();
    let (output, report) = scan(dir.path(), &["long.txt", "--fail-on-unscannable"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["status"], "INCOMPLETE");
}

#[cfg(unix)]
#[test]
fn report_and_baseline_writes_do_not_follow_destination_symlinks() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("clean.txt"), "ordinary\n").unwrap();
    let target = dir.path().join("owned.txt");
    let original = b"{\"version\":\"1.0\",\"entries\":[]}";
    fs::write(&target, original).unwrap();
    let link = dir.path().join("output.json");
    symlink(&target, &link).unwrap();
    for args in [
        vec!["-o", link.to_str().unwrap()],
        vec!["--baseline", link.to_str().unwrap(), "--update-baseline"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .current_dir(dir.path())
            .args(["scan", "clean.txt", "--no-config-discovery"])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(fs::read(&target).unwrap(), original);
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

#[test]
fn unknown_override_names_fail_instead_of_silently_changing_policy() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("clean.txt"), "ordinary\n").unwrap();
    fs::write(
        dir.path().join("config.toml"),
        "[overrides.MisspelledDetector]\nenabled = false\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(dir.path())
        .args([
            "scan",
            "clean.txt",
            "--no-config-discovery",
            "--config",
            "config.toml",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("MisspelledDetector"));
}

#[test]
fn duplicate_detector_names_are_configuration_errors() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("clean.txt"), "ordinary\n").unwrap();
    for (name, config) in [
        (
            "AWSKeyDetector",
            "[[rules]]\nname = 'AWSKeyDetector'\npattern = 'fixture'\nfinding_type = 'Fixture'\n",
        ),
        (
            "RepeatedFixture",
            "[[rules]]\nname = 'RepeatedFixture'\npattern = 'fixture'\nfinding_type = 'Fixture'\n[[rules]]\nname = 'RepeatedFixture'\npattern = 'other'\nfinding_type = 'Fixture'\n",
        ),
    ] {
        fs::write(dir.path().join("config.toml"), config).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .current_dir(dir.path())
            .args([
                "scan",
                "clean.txt",
                "--no-config-discovery",
                "--config",
                "config.toml",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains(name));
    }
}

#[cfg(unix)]
#[test]
fn skipped_symlinks_make_directory_coverage_incomplete() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    symlink("missing.txt", dir.path().join("linked.txt")).unwrap();
    let (output, report) = scan(dir.path(), &[".", "--fail-on-unscannable"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["status"], "INCOMPLETE");
    assert_eq!(report["unscannable"]["count"], 1);
}

#[test]
fn nonfinite_entropy_thresholds_are_configuration_errors() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("clean.txt"), "ordinary\n").unwrap();
    for threshold in ["nan", "inf", "-inf"] {
        fs::write(
            dir.path().join("config.toml"),
            format!("[[rules]]\nname = 'EntropyFixture'\npattern = 'fixture'\nfinding_type = 'Fixture'\nentropy = {threshold}\n"),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .current_dir(dir.path())
            .args([
                "scan",
                "clean.txt",
                "--no-config-discovery",
                "--config",
                "config.toml",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{threshold}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("EntropyFixture"));
    }
}

#[test]
fn binary_filenames_with_separator_text_cannot_become_lockfile_exclusions() {
    let dir = repository();
    let name = "credentials and Cargo.lock";
    fs::write(
        dir.path().join(".gitattributes"),
        "\"credentials and Cargo.lock\" -diff\n",
    )
    .unwrap();
    fs::write(
        dir.path().join(name),
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    let (output, report) = scan(dir.path(), &["--staged"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["file_path"] == name
                && finding["plugin_name"] == "AWSKeyDetector")
    );
    git(dir.path(), &["commit", "--quiet", "-m", "Secret fixture"]);
    git(dir.path(), &["rm", "--quiet", name]);
    git(dir.path(), &["commit", "--quiet", "-m", "Deleted fixture"]);
    let (output, report) = scan(dir.path(), &["--git-history"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["file_path"] == name
                && finding["plugin_name"] == "AWSKeyDetector")
    );
}

#[test]
fn git_control_character_filenames_preserve_staged_and_deleted_history_paths() {
    let dir = repository();
    let mut attributes = String::new();
    let mut names = Vec::new();
    for (escape, character) in [
        ('a', '\u{7}'),
        ('b', '\u{8}'),
        ('f', '\u{c}'),
        ('v', '\u{b}'),
    ] {
        let name = format!("credentials{character}.env");
        attributes.push_str(&format!("\"credentials\\{escape}.env\" -diff\n"));
        fs::write(
            dir.path().join(&name),
            "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
        )
        .unwrap();
        names.push(name);
    }
    fs::write(dir.path().join(".gitattributes"), attributes).unwrap();
    git(dir.path(), &["add", "."]);
    let (output, report) = scan(dir.path(), &["--staged", "--fail-on-unscannable"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["coverage"], "COMPLETE");
    for name in &names {
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["plugin_name"] == "AWSKeyDetector" && finding["file_path"] == *name
                }),
            "Missing staged path: {name:?}"
        );
    }
    git(dir.path(), &["commit", "--quiet", "-m", "Add fixture"]);
    for name in &names {
        fs::remove_file(dir.path().join(name)).unwrap();
    }
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "Delete fixture"]);
    let (output, report) = scan(
        dir.path(),
        &[
            "--git-history",
            "--rev-range",
            "HEAD~1..HEAD",
            "--fail-on-unscannable",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["coverage"], "COMPLETE");
    for name in names {
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["plugin_name"] == "AWSKeyDetector" && finding["file_path"] == name
                }),
            "Missing deleted path: {name:?}"
        );
    }
}

#[test]
fn decoded_multiline_findings_use_the_encoded_source_line() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("input.txt"),
        "ordinary\nb3JkaW5hcnkKQkVHSU4KRU5ECg==\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("rule.toml"),
        "[[rules]]\nname = 'DecodedFixture'\nfinding_type = 'Fixture'\npattern = 'BEGIN\\nEND'\n",
    )
    .unwrap();
    let (_, report) = scan(dir.path(), &["input.txt", "--config", "rule.toml"]);
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["plugin_name"] == "DecodedFixture")
        .unwrap();
    assert_eq!(finding["line_number"], 2);
}

#[test]
fn staged_size_limit_applies_to_the_post_image_not_the_previous_blob() {
    let dir = repository();
    fs::write(dir.path().join("input.txt"), "ordinary\n".repeat(140_000)).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "Large fixture"]);
    fs::write(
        dir.path().join("input.txt"),
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    let (output, report) = scan(
        dir.path(),
        &["--staged", "--max-file-size", "1", "--fail-on-unscannable"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["coverage"], "COMPLETE");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["plugin_name"] == "AWSKeyDetector")
    );
}

#[test]
fn lockfile_inclusion_is_explicit_and_consistent_across_modes() {
    let dir = repository();
    fs::write(
        dir.path().join("Cargo.lock"),
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    for mode in ["Cargo.lock", "--staged"] {
        let (output, report) = scan(dir.path(), &[mode]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(report["excluded"]["count"], 1);
        let (output, report) = scan(dir.path(), &[mode, "--scan-lockfiles"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["plugin_name"] == "AWSKeyDetector")
        );
    }
    git(dir.path(), &["commit", "--quiet", "-m", "Lockfile fixture"]);
    let (output, report) = scan(dir.path(), &["--git-history", "--scan-lockfiles"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["plugin_name"] == "AWSKeyDetector")
    );
}

#[test]
fn report_rule_fingerprint_is_stable_and_changes_with_detector_policy() {
    let dir = repository();
    fs::write(dir.path().join("clean.txt"), "ordinary\n").unwrap();
    let (_, original) = scan(dir.path(), &["clean.txt"]);
    let (_, repeated) = scan(dir.path(), &["clean.txt"]);
    assert_eq!(
        original["detector_fingerprint"],
        repeated["detector_fingerprint"]
    );
    fs::write(
        dir.path().join("policy.toml"),
        "[overrides.PasswordDetector]\nseverity = 'LOW'\n",
    )
    .unwrap();
    let (_, changed) = scan(dir.path(), &["clean.txt", "--config", "policy.toml"]);
    assert_ne!(
        original["detector_fingerprint"],
        changed["detector_fingerprint"]
    );
}
