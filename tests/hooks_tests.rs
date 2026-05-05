use key_watch::cli::CliOptions;
use key_watch::hooks::{generate_pre_commit_hook, generate_pre_push_hook};

#[test]
fn test_hook_generation_pre_commit() {
    let options = CliOptions {
        file: vec![],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: Some("*.log,*.tmp".to_string()),
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_commit_hook(&options);
    assert!(hook.contains("#!/bin/bash"), "Should be bash shebang");
    assert!(hook.contains("KEYWATCH_BIN="), "Should define binary");
    assert!(
        hook.contains("KEYWATCH_BIN='"),
        "Should shell-quote binary assignment"
    );
    assert!(hook.contains("--exclude"), "Should pass exclude patterns");
    assert!(
        hook.contains("EXCLUDE_PATTERNS='*.log,*.tmp'"),
        "Should preserve comma-separated exclude patterns"
    );
}

#[test]
fn test_hook_generation_pre_push() {
    let options = CliOptions {
        file: vec![],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: Some("github.com".to_string()),
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_push_hook(&options);
    assert!(hook.contains("#!/bin/bash"), "Should be bash shebang");
    assert!(
        hook.contains("KEYWATCH_BIN='"),
        "Should shell-quote binary assignment"
    );
    assert!(hook.contains("ALLOWED_REPOS"), "Should set allowed repos");
    assert!(
        hook.contains("CURRENT_REMOTE=$(git remote get-url --push origin"),
        "Should enforce repo restrictions"
    );
}

#[test]
fn test_hook_shell_escaping() {
    let options = CliOptions {
        file: vec![],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: Some("ghp_test'repos123".to_string()),
        blocked_repos: None,
        exclude: Some("test*.txt".to_string()),
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_push_hook(&options);
    assert!(
        hook.contains("'ghp_test'\"'\"'repos123'"),
        "Should escape single quotes"
    );
}

#[test]
fn test_hook_missing_binary_path() {
    let options = CliOptions {
        file: vec![],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_push_hook(&options);
    assert!(
        hook.contains("command -v"),
        "Hook should verify binary is on PATH"
    );
    assert!(
        hook.contains("$KEYWATCH_BIN not found on PATH"),
        "Hook should report missing binary error"
    );
}

#[test]
fn test_hook_missing_detectors_toml() {
    let options = CliOptions {
        file: vec![],
        dir: None,
        output: None,
        verbose: false,
        allowed_repos: None,
        blocked_repos: None,
        exclude: None,
        install_hook: None,
        uninstall_hook: None,
        global: false,
        init: None,
        exit_mode: "strict".to_string(),
        verify_integrity: false,
    };

    let hook = generate_pre_commit_hook(&options);
    assert!(
        !hook.contains("detectors.toml not found"),
        "Hook should rely on binary config lookup"
    );
}

#[test]
fn test_cli_global_hook_requires_install_hook() {
    use clap::Parser;

    let result = CliOptions::try_parse_from(["key-watch", "--global", "--file", "secret.txt"]);
    assert!(result.is_err(), "--global should require --install-hook");
}

#[test]
fn test_cli_global_uninstall_hook_requires_hook_target() {
    use clap::Parser;

    let result =
        CliOptions::try_parse_from(["key-watch", "--global", "--uninstall-hook", "pre-commit"]);
    assert!(result.is_ok(), "--global should work with --uninstall-hook");
}

#[test]
fn test_cli_init_conflicts_with_scan_targets() {
    use clap::Parser;

    let result =
        CliOptions::try_parse_from(["key-watch", "--init", "bash", "--file", "secret.txt"]);
    assert!(result.is_err(), "--init should conflict with scan targets");
}
