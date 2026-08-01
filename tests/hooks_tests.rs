use key_watch::cli::{CliOptions, Command, ExitMode, HookAction, HookInstallArgs, HookType, Shell};
use key_watch::hooks::{generate_pre_commit_hook, generate_pre_push_hook};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

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
        hook.contains("CURRENT_REMOTE=${2:-}"),
        "Should prefer the pushed remote URL from hook argv"
    );
    assert!(
        hook.contains("REMOTE_NAME=${1:-origin}"),
        "Should name the remote explicitly before fallback"
    );
    assert!(
        hook.contains("git remote get-url --push"),
        "Should fall back to the remote name when argv URL is absent"
    );
    assert!(
        hook.contains("normalize_repo"),
        "Should normalize remote and configured repo identities"
    );
    assert!(
        hook.contains("[ \"$CURRENT_REPO\" = \"$allowed_repo\" ]"),
        "Should compare allowed repos by exact identity"
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
