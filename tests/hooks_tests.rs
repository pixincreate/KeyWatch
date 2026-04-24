use key_watch::cli::CliOptions;
use key_watch::hooks::{generate_pre_commit_hook, generate_pre_push_hook};

#[test]
fn test_hook_generation_pre_commit() {
    let options = CliOptions {
        file: None,
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: Some("*.log,*.tmp".to_string()),
        install_hook: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_commit_hook(&options);
    assert!(hook.contains("#!/bin/bash"), "Should be bash shebang");
    assert!(hook.contains("key-watch"), "Should reference binary");
    assert!(hook.contains("--exclude"), "Should pass exclude patterns");
}

#[test]
fn test_hook_generation_pre_push() {
    let options = CliOptions {
        file: None,
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: Some("github.com".to_string()),
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_push_hook(&options);
    assert!(hook.contains("#!/bin/bash"), "Should be bash shebang");
    assert!(hook.contains("ALLOWED_REPOS"), "Should set allowed repos");
}

#[test]
fn test_hook_shell_escaping() {
    let options = CliOptions {
        file: None,
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: Some("ghp_test'repos123".to_string()),
        blocked_repos: None,
        exclude: Some("test*.txt".to_string()),
        install_hook: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_push_hook(&options);
    assert!(
        !hook.contains("test'repos123"),
        "Should escape single quotes"
    );
}

#[test]
fn test_hook_missing_binary_path() {
    let options = CliOptions {
        file: None,
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

    let hook = generate_pre_push_hook(&options);
    assert!(
        hook.contains("command -v"),
        "Hook should verify binary is on PATH"
    );
    assert!(
        hook.contains("key-watch not found"),
        "Hook should report missing binary error"
    );
}

#[test]
fn test_hook_missing_detectors_toml() {
    let options = CliOptions {
        file: None,
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

    let hook = generate_pre_commit_hook(&options);
    assert!(
        hook.contains("detectors.toml not found"),
        "Hook should check config"
    );
}
