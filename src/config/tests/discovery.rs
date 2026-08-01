use super::{minimal_rule_toml, write_file};
use crate::config::KeywatchConfig;
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
    let names: Vec<_> = config.rules.unwrap().into_iter().map(|r| r.name).collect();
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
    let names: Vec<_> = config.rules.unwrap().into_iter().map(|r| r.name).collect();
    assert!(names.contains(&"FileParentRule".to_string()));
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
    let names: Vec<_> = config.rules.unwrap().into_iter().map(|r| r.name).collect();
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
    let msg = result.err().unwrap();
    assert!(
        msg.contains("not found"),
        "error should say 'not found': {msg}"
    );
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
    let names: Vec<_> = config.rules.unwrap().into_iter().map(|r| r.name).collect();
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
    let names: Vec<_> = config.rules.unwrap().into_iter().map(|r| r.name).collect();
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
    let names: Vec<_> = config.rules.unwrap().into_iter().map(|r| r.name).collect();
    assert!(names.contains(&"CwdRule".to_string()));
}
