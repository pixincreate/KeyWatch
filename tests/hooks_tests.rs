use key_watch::cli::{CliOptions, HookInstallArgs, HookType};
use key_watch::hooks::{generate_pre_commit_hook, generate_pre_push_hook};

fn hook_install_args(
    hook_type: HookType,
    allowed_repos: Option<&str>,
    blocked_repos: Option<&str>,
    exclude: Option<&str>,
) -> HookInstallArgs {
    HookInstallArgs {
        hook_type,
        global: false,
        allowed_repos: allowed_repos.map(str::to_string),
        blocked_repos: blocked_repos.map(str::to_string),
        exclude: exclude.map(str::to_string),
    }
}

#[test]
fn test_hook_generation_pre_commit() {
    let options = hook_install_args(HookType::PreCommit, None, None, Some("*.log,*.tmp"));

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
    assert!(
        hook.contains("scan \"$file\""),
        "Should use scan subcommand"
    );
}

#[test]
fn test_hook_generation_pre_push() {
    let options = hook_install_args(HookType::PrePush, Some("github.com"), None, None);

    let hook = generate_pre_push_hook(&options);
    assert!(hook.contains("#!/bin/bash"), "Should be bash shebang");
    assert!(
        hook.contains("KEYWATCH_BIN='"),
        "Should shell-quote binary assignment"
    );
    assert!(hook.contains("ALLOWED_REPOS"), "Should set allowed repos");
    assert!(
        hook.contains("scan . --exit-mode critical"),
        "Should use scan subcommand for pre-push"
    );
    assert!(
        hook.contains("CURRENT_REMOTE=$(git remote get-url --push origin"),
        "Should enforce repo restrictions"
    );
}

#[test]
fn test_hook_shell_escaping() {
    let options = hook_install_args(
        HookType::PrePush,
        Some("ghp_test'repos123"),
        None,
        Some("test*.txt"),
    );

    let hook = generate_pre_push_hook(&options);
    assert!(
        hook.contains("'ghp_test'\"'\"'repos123'"),
        "Should escape single quotes"
    );
}

#[test]
fn test_hook_missing_binary_path() {
    let options = hook_install_args(HookType::PrePush, None, None, None);

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
    let options = hook_install_args(HookType::PreCommit, None, None, None);

    let hook = generate_pre_commit_hook(&options);
    assert!(
        !hook.contains("detectors.toml not found"),
        "Hook should rely on binary config lookup"
    );
}

#[test]
fn test_cli_global_hook_requires_install_hook() {
    use clap::Parser;

    let result = CliOptions::try_parse_from(["key-watch", "scan", "secret.txt", "--global"]);
    assert!(result.is_err(), "--global should be rejected for scan");
}

#[test]
fn test_cli_global_uninstall_hook_requires_hook_target() {
    use clap::Parser;

    let result =
        CliOptions::try_parse_from(["key-watch", "hook", "uninstall", "pre-commit", "--global"]);
    assert!(result.is_ok(), "--global should work with hook uninstall");
}

#[test]
fn test_cli_init_conflicts_with_scan_targets() {
    use clap::Parser;

    let result = CliOptions::try_parse_from(["key-watch", "init", "bash", "secret.txt"]);
    assert!(
        result.is_err(),
        "init should reject extra positional scan targets"
    );
}
