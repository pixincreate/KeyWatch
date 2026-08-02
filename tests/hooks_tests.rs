use key_watch::cli::{CliOptions, Command, ExitMode, HookAction, HookInstallArgs, HookType, Shell};
use key_watch::hooks::{generate_pre_commit_hook, generate_pre_push_hook};
#[cfg(unix)]
use std::{
    fs,
    path::{Path, PathBuf},
    process::Output,
    time::{SystemTime, UNIX_EPOCH},
};

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

#[cfg(unix)]
fn unique_temp_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();

    std::env::temp_dir().join(format!(
        "keywatch_hook_{name}_{stamp}_{}",
        std::process::id()
    ))
}

#[cfg(unix)]
fn write_executable(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, contents).expect("write executable");
    let mut permissions = fs::metadata(path)
        .expect("read executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("mark executable");
}

#[cfg(unix)]
fn generated_binary_name() -> String {
    std::env::current_exe()
        .expect("current test executable should resolve")
        .file_name()
        .expect("current test executable should have a file name")
        .to_string_lossy()
        .into_owned()
}

#[cfg(unix)]
fn run_hook_with_args(
    hook: &str,
    git_script: &str,
    keywatch_script: &str,
    cwd: &Path,
    hook_args: &[&str],
) -> Output {
    let bin_dir = cwd.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    write_executable(&bin_dir.join("git"), git_script);
    write_executable(&bin_dir.join(generated_binary_name()), keywatch_script);

    let hook_path = cwd.join("hook.sh");
    fs::write(&hook_path, hook).expect("write hook");

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    std::process::Command::new("bash")
        .arg(&hook_path)
        .args(hook_args)
        .current_dir(cwd)
        .env("PATH", path)
        .output()
        .expect("run hook")
}

#[cfg(unix)]
fn run_hook(hook: &str, git_script: &str, keywatch_script: &str, cwd: &Path) -> Output {
    run_hook_with_args(hook, git_script, keywatch_script, cwd, &[])
}

#[cfg(unix)]
fn keywatch_script_that_records_args(marker: &Path) -> String {
    format!(
        "#!/bin/bash\nprintf '%s\\n' \"$*\" > '{}'\nexit 0\n",
        marker.display()
    )
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
    assert!(
        hook.contains("[ -L \"$file\" ]"),
        "Should skip staged symlinks"
    );
    assert!(
        hook.contains(">/dev/null 2>&1"),
        "Should suppress scanner output before concise failure"
    );
    assert!(
        !hook.contains("--verbose"),
        "Should not rerun verbosely and print matched secrets"
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
        hook.matches("scan . --exit-mode critical").count() == 1,
        "Should invoke KeyWatch exactly once for scanning"
    );
    assert!(
        hook.contains("resolve_remote_url"),
        "Should keep remote resolution readable in the shell hook"
    );
    assert!(
        hook.contains("normalize_repository_url"),
        "Should keep repository canonicalization readable in the shell hook"
    );
    assert!(
        hook.contains("repository_list_contains"),
        "Should keep exact list membership readable in the shell hook"
    );
    assert!(
        hook.contains("enforce_repository_policy"),
        "Should keep repository policy in the shell hook"
    );
    assert!(
        !hook.contains("*\"$allowed_repo\"*"),
        "Should not use substring allow-list matching"
    );
}

#[cfg(unix)]
#[test]
fn test_pre_commit_failure_output_does_not_print_matched_secret() {
    let temp_dir = unique_temp_dir("pre_commit_secret_output");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    fs::write(temp_dir.join("secret.txt"), "secret").expect("write staged file");

    let hook = generate_pre_commit_hook(&hook_install_args(HookType::PreCommit, None, None, None));
    let git_script =
        "#!/bin/bash\nif [ \"$1\" = \"diff\" ]; then printf 'secret.txt\\0'; exit 0; fi\nexit 1\n";
    let keywatch_script = "#!/bin/bash\nprintf 'MATCHED_SECRET_VALUE\\n'\nprintf 'MATCHED_SECRET_VALUE\\n' >&2\nexit 1\n";
    let output = run_hook(&hook, git_script, keywatch_script, &temp_dir);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(combined.contains("ERROR: Secret detected in secret.txt"));
    assert!(
        !combined.contains("MATCHED_SECRET_VALUE"),
        "Generated pre-commit hook must not print matched secrets"
    );

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_commit_skips_staged_symlinks() {
    let temp_dir = unique_temp_dir("pre_commit_symlink_skip");
    let marker = temp_dir.join("scanner-ran");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    fs::write(temp_dir.join("target.txt"), "secret").expect("write target");
    std::os::unix::fs::symlink("target.txt", temp_dir.join("linked.txt")).expect("create symlink");

    let hook = generate_pre_commit_hook(&hook_install_args(HookType::PreCommit, None, None, None));
    let git_script =
        "#!/bin/bash\nif [ \"$1\" = \"diff\" ]; then printf 'linked.txt\\0'; exit 0; fi\nexit 1\n";
    let keywatch_script = format!("#!/bin/bash\nprintf ran > '{}'\nexit 1\n", marker.display());
    let output = run_hook(&hook, git_script, &keywatch_script, &temp_dir);

    assert!(
        output.status.success(),
        "symlink-only pre-commit should pass"
    );
    assert!(
        !marker.exists(),
        "scanner should not run for staged symlinks"
    );

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_allows_normalized_https_and_scp_equivalent() {
    let temp_dir = unique_temp_dir("pre_push_allowed_normalized");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some(" git@github.com:org/repo.git "),
        None,
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'https://github.com/org/repo.git/\\n'; exit 0; fi\nexit 1\n";
    let keywatch_script = "#!/bin/bash\nexit 0\n";
    let output = run_hook(&hook, git_script, keywatch_script, &temp_dir);

    assert!(
        output.status.success(),
        "normalized HTTPS remote should match SCP allow entry"
    );

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_allows_https_userinfo_case_and_default_port() {
    let temp_dir = unique_temp_dir("pre_push_allowed_url_variants");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some("git@github.com:org/repo.git"),
        None,
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'https://x-access-token:T@GitHub.COM:443/ORG/REPO.git\\n'; exit 0; fi\nexit 1\n";
    let output = run_hook(&hook, git_script, "#!/bin/bash\nexit 0\n", &temp_dir);

    assert!(output.status.success());
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_blocks_https_userinfo_case_and_default_port() {
    let temp_dir = unique_temp_dir("pre_push_blocked_url_variants");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        None,
        Some("ssh://git@github.com/org/repo"),
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'https://user@GitHub.COM:443/ORG/REPO.git\\n'; exit 0; fi\nexit 1\n";
    let output = run_hook(&hook, git_script, "#!/bin/bash\nexit 0\n", &temp_dir);

    assert_eq!(output.status.code(), Some(1));
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_rejects_spoofed_substring_remote() {
    let temp_dir = unique_temp_dir("pre_push_spoofed_remote");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some("git@evil.example:org/repo.git"),
        None,
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'https://evil.example/github.com/org/repo.git\\n'; exit 0; fi\nexit 1\n";
    let keywatch_script = "#!/bin/bash\nexit 0\n";
    let output = run_hook(&hook, git_script, keywatch_script, &temp_dir);

    assert_eq!(output.status.code(), Some(1));

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_blocks_when_actual_pushed_remote_is_unallowed() {
    let temp_dir = unique_temp_dir("pre_push_blocks_actual_unallowed");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some("github.com/org/repo"),
        None,
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'git@github.com:org/repo.git\\n'; exit 0; fi\nexit 1\n";
    let keywatch_script = "#!/bin/bash\nexit 0\n";
    let output = run_hook_with_args(
        &hook,
        git_script,
        keywatch_script,
        &temp_dir,
        &["mirror", "https://evil.example/org/repo.git"],
    );

    assert_eq!(output.status.code(), Some(1));

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_blocks_when_actual_pushed_remote_is_blocked() {
    let temp_dir = unique_temp_dir("pre_push_blocks_actual_blocked");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        None,
        Some("https://evil.example/org/repo.git"),
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'git@github.com:org/repo.git\\n'; exit 0; fi\nexit 1\n";
    let keywatch_script = "#!/bin/bash\nexit 0\n";
    let output = run_hook_with_args(
        &hook,
        git_script,
        keywatch_script,
        &temp_dir,
        &["origin", "https://evil.example/org/repo.git"],
    );

    assert_eq!(output.status.code(), Some(1));

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_blocks_normalized_https_and_scp_equivalent() {
    let temp_dir = unique_temp_dir("pre_push_blocked_normalized");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        None,
        Some("https://github.com/org/repo"),
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'git@github.com:org/repo.git\\n'; exit 0; fi\nexit 1\n";
    let keywatch_script = "#!/bin/bash\nexit 0\n";
    let output = run_hook(&hook, git_script, keywatch_script, &temp_dir);

    assert_eq!(output.status.code(), Some(1));

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_uses_named_remote_push_url_when_argv_url_is_absent() {
    let temp_dir = unique_temp_dir("pre_push_named_push_url");
    let marker = temp_dir.join("keywatch-args");
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some("https://push.example/org/repo.git"),
        None,
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1 $2 $3\" = \"remote get-url --push\" ] && [ \"$4\" = \"mirror\" ]; then printf 'https://push.example/org/repo.git\\n'; exit 0; fi\nif [ \"$1 $2 $3\" = \"remote get-url mirror\" ]; then printf 'https://fetch.example/org/repo.git\\n'; exit 0; fi\nexit 1\n";
    let output = run_hook_with_args(
        &hook,
        git_script,
        &keywatch_script_that_records_args(&marker),
        &temp_dir,
        &["mirror"],
    );

    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(&marker).expect("read scanner args"),
        "scan . --exit-mode critical\n"
    );
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_falls_back_to_named_remote_fetch_url() {
    let temp_dir = unique_temp_dir("pre_push_named_fetch_url");
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some("https://fetch.example/org/repo.git"),
        None,
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1 $2 $3\" = \"remote get-url --push\" ]; then exit 1; fi\nif [ \"$1 $2\" = \"remote get-url\" ] && [ \"$3\" = \"mirror\" ]; then printf 'https://fetch.example/org/repo.git\\n'; exit 0; fi\nexit 1\n";
    let output = run_hook_with_args(
        &hook,
        git_script,
        "#!/bin/bash\nexit 0\n",
        &temp_dir,
        &["mirror"],
    );

    assert!(output.status.success());
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_ignores_invalid_configured_entries() {
    let temp_dir = unique_temp_dir("pre_push_invalid_config_entries");
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some("not-a-repo,https://github.com/org/repo"),
        Some("not-a-repo"),
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'git@github.com:org/repo.git\\n'; exit 0; fi\nexit 1\n";
    let output = run_hook(&hook, git_script, "#!/bin/bash\nexit 0\n", &temp_dir);

    assert!(output.status.success());
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_fails_closed_for_unnormalizable_remote_when_filters_exist() {
    let temp_dir = unique_temp_dir("pre_push_invalid_remote_filtered");
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(
        HookType::PrePush,
        Some("https://github.com/org/repo"),
        None,
        None,
    ));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'not-a-repo\\n'; exit 0; fi\nexit 1\n";
    let output = run_hook(&hook, git_script, "#!/bin/bash\nexit 0\n", &temp_dir);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Error: unable to validate remote not-a-repo")
    );
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_scans_unnormalizable_remote_when_no_filters_exist() {
    let temp_dir = unique_temp_dir("pre_push_invalid_remote_unfiltered");
    let marker = temp_dir.join("keywatch-args");
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let hook = generate_pre_push_hook(&hook_install_args(HookType::PrePush, None, None, None));
    let git_script = "#!/bin/bash\nif [ \"$1\" = \"remote\" ]; then printf 'not-a-repo\\n'; exit 0; fi\nexit 1\n";
    let output = run_hook(
        &hook,
        git_script,
        &keywatch_script_that_records_args(&marker),
        &temp_dir,
    );

    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(&marker).expect("read scanner args"),
        "scan . --exit-mode critical\n"
    );
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn test_pre_push_ignores_repository_config_that_disables_scanning() {
    let temp_dir = unique_temp_dir("pre_push_ignores_repository_config");
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    fs::write(temp_dir.join(".keywatch.toml"), "exclude = [\"**/*\"]\n")
        .expect("write repository config");
    fs::write(
        temp_dir.join("secret.txt"),
        "master_api_key = \"abcdefghijklmnopqrstuvwxyz1234\"\n",
    )
    .expect("write critical secret");

    let hook = generate_pre_push_hook(&hook_install_args(HookType::PrePush, None, None, None));
    let keywatch_script = format!(
        "#!/bin/bash\nKEYWATCH_CONFIG_PATH=\"{}\" exec \"{}\" \"$@\"\n",
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("detectors.toml")
            .display(),
        env!("CARGO_BIN_EXE_key-watch")
    );
    let output = run_hook(
        &hook,
        &["origin"],
        "#!/bin/bash\nexit 1\n",
        &keywatch_script,
        &temp_dir,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "repository config must not suppress pre-push scanning: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
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
fn test_cli_scan_rejects_global_flag() {
    use clap::Parser;

    let result = CliOptions::try_parse_from(["key-watch", "scan", "secret.txt", "--global"]);
    assert!(result.is_err(), "--global should be rejected for scan");
}

#[test]
fn test_cli_hook_uninstall_accepts_global_flag() {
    use clap::Parser;

    let result =
        CliOptions::try_parse_from(["key-watch", "hook", "uninstall", "pre-commit", "--global"]);
    assert!(result.is_ok(), "--global should work with hook uninstall");
}

#[test]
fn test_cli_hook_install_pre_commit_parses_successfully() {
    use clap::Parser;

    let options = CliOptions::try_parse_from(["key-watch", "hook", "install", "pre-commit"])
        .expect("pre-commit install should parse");
    options
        .validate()
        .expect("validated hook install should succeed");

    match options.command {
        Command::Hook(args) => match args.action {
            HookAction::Install(install_args) => {
                assert_eq!(install_args.hook_type, HookType::PreCommit);
                assert!(!install_args.global, "global should default to false");
            }
            _ => panic!("expected install action"),
        },
        _ => panic!("expected hook command"),
    }
}

#[test]
fn test_cli_hook_install_pre_push_global_parses_successfully() {
    use clap::Parser;

    let options =
        CliOptions::try_parse_from(["key-watch", "hook", "install", "pre-push", "--global"])
            .expect("pre-push install should parse");
    options
        .validate()
        .expect("validated hook install should succeed");

    match options.command {
        Command::Hook(args) => match args.action {
            HookAction::Install(install_args) => {
                assert_eq!(install_args.hook_type, HookType::PrePush);
                assert!(install_args.global, "global flag should be preserved");
            }
            _ => panic!("expected install action"),
        },
        _ => panic!("expected hook command"),
    }
}

#[test]
fn test_cli_scan_defaults_to_strict_exit_mode() {
    use clap::Parser;

    let options = CliOptions::try_parse_from(["key-watch", "scan", "secret.txt"])
        .expect("scan command should parse");

    match options.command {
        Command::Scan(scan_args) => {
            assert_eq!(scan_args.exit_mode, ExitMode::Strict);
        }
        _ => panic!("expected scan command"),
    }
}

#[test]
fn test_cli_scan_can_disable_config_discovery() {
    use clap::Parser;

    let options = CliOptions::try_parse_from([
        "key-watch",
        "scan",
        ".",
        "--no-config-discovery",
        "--config",
        "trusted.toml",
    ])
    .expect("trusted explicit config with disabled discovery should parse");

    match options.command {
        Command::Scan(scan_args) => {
            assert!(scan_args.no_config_discovery);
            assert_eq!(scan_args.config.as_deref(), Some("trusted.toml"));
        }
        _ => panic!("expected scan command"),
    }
}

#[cfg(unix)]
#[test]
fn test_cli_scan_ignores_repository_config_when_discovery_is_disabled() {
    let temp_dir = unique_temp_dir("disabled_config_discovery");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    fs::write(temp_dir.join(".keywatch.toml"), "exclude = [\"**/*\"]\n")
        .expect("write repository config");
    fs::write(
        temp_dir.join("secret.txt"),
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
    )
    .expect("write secret fixture");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args([
            "scan",
            temp_dir.to_str().expect("temp path should be UTF-8"),
            "--no-config-discovery",
        ])
        .output()
        .expect("run key-watch");

    assert_eq!(output.status.code(), Some(1));
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[test]
fn test_cli_pre_commit_rejects_blocked_repos() {
    use clap::Parser;

    let options = CliOptions::try_parse_from([
        "key-watch",
        "hook",
        "install",
        "pre-commit",
        "--blocked-repos",
        "github.com/example/repo",
    ])
    .expect("clap parsing should succeed");

    let error = options
        .validate()
        .expect_err("pre-commit should reject blocked repos");
    assert!(
        error.contains("--allowed-repos and --blocked-repos are only supported for pre-push hooks")
    );
}

#[test]
fn test_cli_init_accepts_supported_shells() {
    use clap::Parser;

    for (shell_name, expected_shell) in [
        ("bash", Shell::Bash),
        ("zsh", Shell::Zsh),
        ("fish", Shell::Fish),
        ("posix", Shell::Posix),
    ] {
        let options = CliOptions::try_parse_from(["key-watch", "init", shell_name])
            .expect("supported shell should parse");

        match options.command {
            Command::Init { shell } => assert_eq!(shell, expected_shell),
            _ => panic!("expected init command"),
        }
    }
}

#[test]
fn test_cli_pre_commit_rejects_repo_filters() {
    use clap::Parser;

    let options = CliOptions::try_parse_from([
        "key-watch",
        "hook",
        "install",
        "pre-commit",
        "--allowed-repos",
        "github.com/example/repo",
    ])
    .expect("clap parsing should succeed");

    let error = options
        .validate()
        .expect_err("pre-commit should reject repo filters");
    assert!(
        error.contains("--allowed-repos and --blocked-repos are only supported for pre-push hooks")
    );
}

#[test]
fn test_cli_pre_push_rejects_exclude() {
    use clap::Parser;

    let options = CliOptions::try_parse_from([
        "key-watch",
        "hook",
        "install",
        "pre-push",
        "--exclude",
        "target",
    ])
    .expect("clap parsing should succeed");

    let error = options
        .validate()
        .expect_err("pre-push should reject exclude patterns");
    assert!(error.contains("--exclude is only supported for pre-commit hooks"));
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
