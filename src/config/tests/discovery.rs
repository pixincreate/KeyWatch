use super::{minimal_rule_toml, write_file};
use crate::config::{ConfigError, KeywatchConfig};
use tempfile::TempDir;

#[test]
fn test_config_discovery_directory_root() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        ".keywatch.toml",
        &minimal_rule_toml("DirRule", r"\\bDIR\\b", "HIGH"),
    );

    let paths = vec![dir.path().to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths)
        .unwrap()
        .expect("config should be found in directory");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(names.contains(&"DirRule".to_string()));
}

#[test]
fn test_config_discovery_file_parent() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        ".keywatch.toml",
        &minimal_rule_toml("FileParentRule", r"\\bFP\\b", "MEDIUM"),
    );
    let scan_file = write_file(&dir, "secrets.txt", "some content");

    let paths = vec![scan_file.to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths)
        .unwrap()
        .expect("config should be found in file's parent directory");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(names.contains(&"FileParentRule".to_string()));
}

#[test]
fn test_config_discovery_walks_up_to_ancestor_directories() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        ".keywatch.toml",
        &minimal_rule_toml("RootRule", r"\\bROOT\\b", "HIGH"),
    );
    let nested = dir.path().join("proto").join("payments");
    std::fs::create_dir_all(&nested).unwrap();
    let scan_file = nested.join("payment.proto");
    std::fs::write(&scan_file, "message Payment {}").unwrap();

    let paths = vec![scan_file.to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths)
        .unwrap()
        .expect("root config should apply to nested scan paths");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(names.contains(&"RootRule".to_string()));
}

#[test]
fn test_config_discovery_stops_at_repository_root() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        ".keywatch.toml",
        &minimal_rule_toml("OutsideRule", r"\\bOUT\\b", "HIGH"),
    );
    let repo_root = dir.path().join("repo");
    std::fs::create_dir_all(repo_root.join(".git")).unwrap();
    let scan_file = repo_root.join("secrets.txt");
    std::fs::write(&scan_file, "some content").unwrap();

    let paths = vec![scan_file.to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths).unwrap();
    assert!(
        config.is_none(),
        "config above the repository root must not be trusted"
    );
}

#[test]
fn test_config_discovery_nearest_config_wins_over_ancestor() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        ".keywatch.toml",
        &minimal_rule_toml("RootRule", r"\\bROOT\\b", "HIGH"),
    );
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        nested.join(".keywatch.toml"),
        minimal_rule_toml("NearRule", r"\\bNEAR\\b", "LOW"),
    )
    .unwrap();
    let scan_file = nested.join("secrets.txt");
    std::fs::write(&scan_file, "some content").unwrap();

    let paths = vec![scan_file.to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths)
        .unwrap()
        .expect("nearest config should be found");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(names.contains(&"NearRule".to_string()), "nearest wins");
    assert!(
        !names.contains(&"RootRule".to_string()),
        "ancestor config must not shadow the nearest one"
    );
}

#[test]
fn test_explicit_config_takes_precedence() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, ".keywatch.toml", "# empty");
    let explicit_dir = TempDir::new().unwrap();
    let explicit_cfg = write_file(
        &explicit_dir,
        "explicit.toml",
        &minimal_rule_toml("ExplicitRule", r"\\bEXP\\b", "CRITICAL"),
    );

    let paths = vec![dir.path().to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(Some(explicit_cfg.to_str().unwrap()), &paths)
        .unwrap()
        .expect("explicit config must be loaded");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(names.contains(&"ExplicitRule".to_string()));
}

#[test]
fn test_no_paths_no_config_in_cwd_returns_ok() {
    let result = KeywatchConfig::load_for_paths(None, &[]);
    assert!(result.is_ok());
}

#[test]
fn test_explicit_nonexistent_path_returns_error() {
    let result = KeywatchConfig::load_for_paths(Some("/nonexistent/path/config.toml"), &[]);
    assert!(result.is_err());
    match result.err().unwrap() {
        ConfigError::NotFound { path } => {
            assert_eq!(path, "/nonexistent/path/config.toml");
        }
        other => panic!("expected NotFound error, got {other:?}"),
    }
}

#[test]
fn test_candidate_filename_order_keywatch_toml_before_kw_toml() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "keywatch.toml",
        &minimal_rule_toml("KW", r"\\bKW\\b", "LOW"),
    );
    write_file(
        &dir,
        ".kw.toml",
        &minimal_rule_toml("KWShort", r"\\bKWS\\b", "LOW"),
    );

    let paths = vec![dir.path().to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths)
        .unwrap()
        .expect("should find keywatch.toml");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(
        names.contains(&"KW".to_string()),
        "keywatch.toml should win"
    );
    assert!(
        !names.contains(&"KWShort".to_string()),
        ".kw.toml must not be picked"
    );
}

#[test]
fn test_candidate_filename_dotted_wins_over_plain() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        ".keywatch.toml",
        &minimal_rule_toml("Dotted", r"\\bDT\\b", "LOW"),
    );
    write_file(
        &dir,
        "keywatch.toml",
        &minimal_rule_toml("Plain", r"\\bPL\\b", "LOW"),
    );

    let paths = vec![dir.path().to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths)
        .unwrap()
        .expect("should find .keywatch.toml");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(
        names.contains(&"Dotted".to_string()),
        ".keywatch.toml should win"
    );
    assert!(
        !names.contains(&"Plain".to_string()),
        "keywatch.toml must not be picked"
    );
}

#[test]
fn test_load_none_uses_supplied_cwd() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        ".keywatch.toml",
        &minimal_rule_toml("CwdRule", r"\\bCWD\\b", "LOW"),
    );

    let config = KeywatchConfig::load_for_paths_at_cwd(None, &[], dir.path())
        .unwrap()
        .expect("config should be found in supplied cwd");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(names.contains(&"CwdRule".to_string()));
}

#[test]
fn test_config_in_world_writable_directory_is_ignored() {
    // On a shared host any user can drop a config into a world-writable
    // directory; trusting it would let them disable detectors for everyone
    // scanning beneath it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            ".keywatch.toml",
            &minimal_rule_toml("HostileRule", r"\\bX\\b", "LOW"),
        );
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(dir.path(), perms).unwrap();
        let scan_file = dir.path().join("secrets.txt");
        std::fs::write(&scan_file, "content").unwrap();

        let paths = vec![scan_file.to_str().unwrap().to_string()];
        assert!(
            KeywatchConfig::load_for_paths(None, &paths)
                .unwrap()
                .is_none(),
            "config from a world-writable directory must not be trusted"
        );
    }
}

#[test]
fn test_config_at_repository_root_applies_to_nested_paths() {
    // The candidate check must run before the .git stop check, or a config
    // sitting AT the repo root stops being discovered. Both existing walk
    // tests pass either way, so this pins the ordering.
    let dir = TempDir::new().unwrap();
    let repo_root = dir.path().join("repo");
    std::fs::create_dir_all(repo_root.join(".git")).unwrap();
    std::fs::write(
        repo_root.join(".keywatch.toml"),
        minimal_rule_toml("RootRule", r"\\bROOT\\b", "HIGH"),
    )
    .unwrap();
    let nested = repo_root.join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let scan_file = nested.join("secrets.txt");
    std::fs::write(&scan_file, "content").unwrap();

    let paths = vec![scan_file.to_str().unwrap().to_string()];
    let config = KeywatchConfig::load_for_paths(None, &paths)
        .unwrap()
        .expect("a config at the repository root must apply to nested paths");
    let names: Vec<_> = config
        .rules
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert!(names.contains(&"RootRule".to_string()));
}
