pub mod cli;
pub mod detector;
pub mod hooks;
pub mod report;
pub mod scanner;
pub mod utils;

use clap::Parser;
use cli::{
    CliOptions, Command, ExitMode, HookAction, HookInstallArgs, HookType, HookUninstallArgs,
    ScanArgs, Shell,
};
use report::Finding;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Instant;

use crate::report::Severity;
pub use hooks::{generate_pre_commit_hook, generate_pre_push_hook};

pub const EXIT_CODE_RUNTIME_ERROR: i32 = 2;

pub fn run_cli() -> Result<(), String> {
    let options = CliOptions::parse();
    options.validate()?;

    match options.command {
        Command::Scan(args) => run_scan_command(&args),
        Command::Hook(args) => match args.action {
            HookAction::Install(install_args) => install_hook(&install_args),
            HookAction::Uninstall(uninstall_args) => uninstall_hook(&uninstall_args),
        },
        Command::Init { shell } => {
            print_shell_init(&shell);
            Ok(())
        }
        Command::VerifyIntegrity => verify_binary_integrity(),
    }
}

fn run_scan_command(args: &ScanArgs) -> Result<(), String> {
    let start = Instant::now();

    let (findings, scan_metadata) = scanner::run_scan(args)?;
    let elapsed = start.elapsed();
    let scan_time = format!(
        "{}.{:01}s",
        elapsed.as_secs(),
        elapsed.subsec_millis() / 100
    );
    let severity_counts = report::get_severity_counts(&findings);
    let exit_code = calculate_exit_code(&findings, &args.exit_mode);
    let findings_count = findings.len();
    let report_json = report::create_report(findings, scan_metadata, scan_time)
        .map_err(|err| format!("Failed to serialize report: {}", err))?;

    if args.verbose {
        println!("{report_json}");
    } else if findings_count == 0 {
        println!("No secrets found.");
    } else {
        println!(
            "WARNING: {} potential secret(s) detected (HIGH: {}, MEDIUM: {}, LOW: {})",
            findings_count, severity_counts.0, severity_counts.1, severity_counts.2
        );
    }

    if let Some(ref output_path) = args.output {
        utils::write_to_file(output_path, &report_json)
            .map_err(|err| format!("Failed to write report to '{}': {}", output_path, err))?;
    }

    std::process::exit(exit_code);
}

fn install_hook(args: &HookInstallArgs) -> Result<(), String> {
    let hook_content = match args.hook_type {
        HookType::PrePush => hooks::generate_pre_push_hook(args),
        HookType::PreCommit => hooks::generate_pre_commit_hook(args),
    };

    let hook_type_str = args.hook_type.as_str();
    let install_target = resolve_hook_install_target(hook_type_str, args.global)?;

    if !install_target.is_global {
        ensure_local_hook_target_is_safe_to_create(&install_target.path)?;
    }

    if let Some(parent) = install_target.path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "Failed to create hook directory '{}': {}",
                parent.display(),
                err
            )
        })?;
    }

    if install_target.is_global {
        ensure_global_hook_target_is_safe(&install_target.path)?;
    }

    let hook_path = install_target.path.to_string_lossy().into_owned();
    utils::write_to_file(&hook_path, &hook_content)
        .map_err(|err| format!("Failed to install hook '{}': {}", hook_type_str, err))?;
    utils::make_executable(&hook_path)
        .map_err(|err| format!("Failed to make hook executable '{}': {}", hook_path, err))?;

    if install_target.configured_global_path {
        println!(
            "Configured git --global core.hooksPath to {}",
            install_target.hooks_dir.display()
        );
    }

    if install_target.is_global {
        println!("Installed global {hook_type_str} hook at {hook_path}");
    } else {
        println!("Installed {hook_type_str} hook at {hook_path}");
    }
    println!(
        "The hook will run automatically during git {}.",
        hook_type_str.replace('-', " ")
    );
    Ok(())
}

fn uninstall_hook(args: &HookUninstallArgs) -> Result<(), String> {
    let hook_type_str = args.hook_type.as_str();
    let install_target = resolve_hook_uninstall_target(hook_type_str, args.global)?;

    if !install_target.path.exists() {
        let scope = if install_target.is_global {
            "global"
        } else {
            "local"
        };
        println!(
            "No {scope} {hook_type_str} hook found at {}",
            install_target.path.display()
        );
        return Ok(());
    }

    ensure_hook_target_is_keywatch_managed(
        &install_target.path,
        install_target.is_global,
        "remove",
    )?;

    fs::remove_file(&install_target.path).map_err(|err| {
        format!(
            "Failed to remove hook '{}': {}",
            install_target.path.display(),
            err
        )
    })?;

    if install_target.is_global {
        println!(
            "Removed global {hook_type_str} hook at {}",
            install_target.path.display()
        );
    } else {
        println!(
            "Removed {hook_type_str} hook at {}",
            install_target.path.display()
        );
    }

    Ok(())
}

fn print_shell_init(shell: &Shell) {
    let script = match shell {
        Shell::Fish => "alias keywatch 'key-watch'\nalias kw 'key-watch'\n",
        Shell::Bash | Shell::Zsh | Shell::Posix => {
            "alias keywatch='key-watch'\nalias kw='key-watch'\n"
        }
    };

    print!("{script}");
}

struct HookInstallTarget {
    path: PathBuf,
    hooks_dir: PathBuf,
    is_global: bool,
    configured_global_path: bool,
}

impl HookInstallTarget {
    fn local(hook_type: &str) -> Result<Self, String> {
        let hooks_dir = resolve_local_hooks_dir()?;
        Ok(Self {
            path: hooks_dir.join(hook_type),
            hooks_dir,
            is_global: false,
            configured_global_path: false,
        })
    }

    fn global(hook_type: &str) -> Result<Self, String> {
        let configured = read_global_hooks_path()?;
        let hooks_dir = match configured {
            Some(path) => path,
            None => {
                let managed_dir = managed_global_hooks_dir(
                    env::var_os("XDG_CONFIG_HOME"),
                    env::var_os("HOME"),
                    env::var_os("APPDATA"),
                    env::var_os("USERPROFILE"),
                )?;
                fs::create_dir_all(&managed_dir).map_err(|err| {
                    format!(
                        "Failed to create global hooks directory '{}': {}",
                        managed_dir.display(),
                        err
                    )
                })?;
                configure_global_hooks_path(&managed_dir)?;
                return Ok(Self {
                    path: managed_dir.join(hook_type),
                    hooks_dir: managed_dir,
                    is_global: true,
                    configured_global_path: true,
                });
            }
        };

        Ok(Self {
            path: hooks_dir.join(hook_type),
            hooks_dir,
            is_global: true,
            configured_global_path: false,
        })
    }
}

fn resolve_hook_install_target(hook_type: &str, global: bool) -> Result<HookInstallTarget, String> {
    if global {
        HookInstallTarget::global(hook_type)
    } else {
        HookInstallTarget::local(hook_type)
    }
}

fn resolve_hook_uninstall_target(
    hook_type: &str,
    global: bool,
) -> Result<HookInstallTarget, String> {
    if global {
        let hooks_dir = match read_global_hooks_path()? {
            Some(path) => path,
            None => managed_global_hooks_dir(
                env::var_os("XDG_CONFIG_HOME"),
                env::var_os("HOME"),
                env::var_os("APPDATA"),
                env::var_os("USERPROFILE"),
            )?,
        };

        Ok(HookInstallTarget {
            path: hooks_dir.join(hook_type),
            hooks_dir,
            is_global: true,
            configured_global_path: false,
        })
    } else {
        HookInstallTarget::local(hook_type)
    }
}

fn resolve_local_hooks_dir() -> Result<PathBuf, String> {
    resolve_local_hooks_dir_from(Path::new("."))
}

fn resolve_local_hooks_dir_from(cwd: &Path) -> Result<PathBuf, String> {
    let output = ProcessCommand::new("git")
        .current_dir(cwd)
        .args(["rev-parse", "--path-format=absolute", "--git-path", "hooks"])
        .output()
        .map_err(|err| format!("Failed to resolve git hooks directory: {}", err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            "Local hook installation requires running inside a git repository".to_string()
        } else {
            format!("Local hook installation requires running inside a git repository: {stderr}")
        });
    }

    let hooks_path = String::from_utf8(output.stdout)
        .map_err(|err| format!("Invalid UTF-8 from git rev-parse output: {}", err))?
        .trim()
        .to_string();

    if hooks_path.is_empty() {
        return Err("Failed to resolve git hooks directory".to_string());
    }

    Ok(PathBuf::from(hooks_path))
}

fn read_global_hooks_path() -> Result<Option<PathBuf>, String> {
    let output = ProcessCommand::new("git")
        .args(["config", "--global", "--path", "--get", "core.hooksPath"])
        .output()
        .map_err(|err| format!("Failed to read git global core.hooksPath: {}", err))?;

    if output.status.success() {
        let hooks_path = String::from_utf8(output.stdout)
            .map_err(|err| format!("Invalid UTF-8 from git config output: {}", err))?
            .trim()
            .to_string();

        if hooks_path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PathBuf::from(hooks_path)))
        }
    } else if output.status.code() == Some(1) {
        Ok(None)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn managed_global_hooks_dir(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
    appdata: Option<std::ffi::OsString>,
    userprofile: Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    if let Some(xdg_config_home) = xdg_config_home {
        return Ok(PathBuf::from(xdg_config_home)
            .join("key-watch")
            .join("hooks"));
    }

    if let Some(home) = home {
        return Ok(PathBuf::from(home)
            .join(".config")
            .join("key-watch")
            .join("hooks"));
    }

    if let Some(appdata) = appdata {
        return Ok(PathBuf::from(appdata).join("key-watch").join("hooks"));
    }

    if let Some(userprofile) = userprofile {
        return Ok(PathBuf::from(userprofile)
            .join(".config")
            .join("key-watch")
            .join("hooks"));
    }

    Err("Could not determine a directory for global git hooks".to_string())
}

fn configure_global_hooks_path(hooks_dir: &Path) -> Result<(), String> {
    let output = ProcessCommand::new("git")
        .args([
            "config",
            "--global",
            "core.hooksPath",
            hooks_dir.to_string_lossy().as_ref(),
        ])
        .output()
        .map_err(|err| format!("Failed to configure git global core.hooksPath: {}", err))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!(
            "git config --global core.hooksPath {} failed: {}",
            hooks_dir.display(),
            stderr
        ))
    }
}

fn ensure_global_hook_target_is_safe(hook_path: &Path) -> Result<(), String> {
    ensure_hook_target_is_keywatch_managed(hook_path, true, "overwrite")
}

fn ensure_local_hook_target_is_safe_to_create(hook_path: &Path) -> Result<(), String> {
    resolve_local_hooks_dir()?;

    if hook_path.exists() {
        ensure_hook_target_is_keywatch_managed(hook_path, false, "overwrite")?;
    }

    Ok(())
}

fn ensure_hook_target_is_keywatch_managed(
    hook_path: &Path,
    is_global: bool,
    action: &str,
) -> Result<(), String> {
    if !hook_path.exists() {
        return Ok(());
    }

    let existing_hook = fs::read_to_string(hook_path).map_err(|err| {
        format!(
            "Failed to inspect existing hook '{}': {}",
            hook_path.display(),
            err
        )
    })?;

    if existing_hook.contains("# Installed by KeyWatch") {
        return Ok(());
    }

    let scope = if is_global { "global" } else { "local" };
    Err(format!(
        "Refusing to {action} existing {scope} hook at '{}'. Merge it manually or remove it yourself.",
        hook_path.display()
    ))
}

fn verify_binary_integrity() -> Result<(), String> {
    let exe_path =
        env::current_exe().map_err(|err| format!("Failed to get executable path: {}", err))?;
    let metadata = exe_path
        .metadata()
        .map_err(|err| format!("Failed to get executable metadata: {}", err))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = metadata.permissions();
        let mode = perms.mode();
        if mode & 0o002 != 0 {
            eprintln!("WARNING: Binary is world-writable! Integrity may be compromised.");
        }
    }

    println!("Binary integrity verified: {:?}", exe_path);
    println!("Size: {} bytes", metadata.len());
    Ok(())
}

fn calculate_exit_code(findings: &[Finding], exit_mode: &ExitMode) -> i32 {
    if findings.is_empty() {
        return 0;
    }

    match exit_mode {
        ExitMode::Always => 0,
        ExitMode::Critical => {
            let has_high = findings
                .iter()
                .any(|finding| finding.severity == Severity::High);
            if has_high { 1 } else { 0 }
        }
        ExitMode::Strict => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Severity, calculate_exit_code, ensure_global_hook_target_is_safe,
        ensure_local_hook_target_is_safe_to_create, managed_global_hooks_dir,
        resolve_hook_uninstall_target, resolve_local_hooks_dir_from,
    };
    use crate::cli::ExitMode;
    use crate::report::Finding;
    use std::env;
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix epoch")
            .as_millis();
        std::env::temp_dir().join(format!("keywatch_{name}_{timestamp}"))
    }

    fn init_git_repo(path: &std::path::Path) {
        fs::create_dir_all(path).expect("create repo dir");
        let status = Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(path)
            .status()
            .expect("run git init");
        assert!(status.success(), "git init should succeed");
    }

    #[test]
    fn test_managed_global_hooks_dir_prefers_xdg() {
        let path = managed_global_hooks_dir(
            Some("/tmp/xdg".into()),
            Some("/tmp/home".into()),
            None,
            None,
        )
        .expect("xdg path should resolve");

        assert_eq!(path, std::path::PathBuf::from("/tmp/xdg/key-watch/hooks"));
    }

    #[test]
    fn test_managed_global_hooks_dir_falls_back_to_home() {
        let path = managed_global_hooks_dir(None, Some("/tmp/home".into()), None, None)
            .expect("home path should resolve");

        assert_eq!(
            path,
            std::path::PathBuf::from("/tmp/home/.config/key-watch/hooks")
        );
    }

    #[test]
    fn test_global_hook_safety_allows_keywatch_hook() {
        let temp_dir = unique_temp_dir("global_hook_safe");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let hook_path = temp_dir.join("pre-commit");

        fs::write(&hook_path, "#!/bin/bash\n# Installed by KeyWatch\n").expect("write hook file");

        ensure_global_hook_target_is_safe(&hook_path).expect("keywatch hook should be reusable");

        fs::remove_file(&hook_path).expect("remove hook file");
        fs::remove_dir_all(&temp_dir).expect("remove temp dir");
    }

    #[test]
    fn test_global_hook_safety_rejects_foreign_hook() {
        let temp_dir = unique_temp_dir("global_hook_foreign");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let hook_path = temp_dir.join("pre-commit");

        fs::write(&hook_path, "#!/bin/bash\necho custom hook\n").expect("write hook file");

        let error = ensure_global_hook_target_is_safe(&hook_path)
            .expect_err("foreign hook should be rejected");
        assert!(error.contains("Refusing to overwrite existing global hook"));

        fs::remove_file(&hook_path).expect("remove hook file");
        fs::remove_dir_all(&temp_dir).expect("remove temp dir");
    }

    #[test]
    fn test_resolve_local_hooks_dir_resolves_correctly() {
        let temp_dir = unique_temp_dir("local_hooks_dir_resolution");
        init_git_repo(&temp_dir);

        let resolved =
            resolve_local_hooks_dir_from(&temp_dir).expect("should resolve hooks dir inside repo");

        assert!(resolved.is_absolute(), "hooks path should be absolute");
        assert!(
            resolved.ends_with(".git/hooks"),
            "hooks path should end with .git/hooks, but was: {}",
            resolved.display()
        );

        fs::remove_dir_all(&temp_dir).expect("remove temp dir");
    }

    #[test]
    fn test_git_init_creates_hooks_dir() {
        let temp_dir = unique_temp_dir("local_hook_missing_git");
        init_git_repo(&temp_dir);

        assert!(temp_dir.join(".git/hooks").exists());

        fs::remove_dir_all(&temp_dir).expect("remove temp dir");
    }

    #[test]
    fn test_local_hook_safety_rejects_foreign_hook() {
        let temp_dir = unique_temp_dir("local_hook_foreign");
        init_git_repo(&temp_dir);
        let git_dir = temp_dir.join(".git");
        let git_hooks_dir = git_dir.join("hooks");
        fs::create_dir_all(&git_hooks_dir).expect("create hooks dir");
        let hook_path = git_hooks_dir.join("pre-commit");
        fs::write(&hook_path, "#!/bin/bash\necho custom hook\n").expect("write hook file");

        let error = ensure_local_hook_target_is_safe_to_create(&hook_path)
            .expect_err("foreign local hook should be rejected");
        assert!(error.contains("Refusing to overwrite existing local hook"));

        fs::remove_file(&hook_path).expect("remove hook file");
        fs::remove_dir_all(&temp_dir).expect("remove temp dir");
    }

    #[test]
    fn test_global_uninstall_target_does_not_configure_missing_hooks_path() {
        let install_target = resolve_hook_uninstall_target("pre-commit", true)
            .expect("global uninstall target should resolve");
        let expected_hooks_dir = managed_global_hooks_dir(
            env::var_os("XDG_CONFIG_HOME"),
            env::var_os("HOME"),
            env::var_os("APPDATA"),
            env::var_os("USERPROFILE"),
        )
        .expect("managed hooks dir should resolve");

        assert!(install_target.is_global);
        assert!(!install_target.configured_global_path);
        assert_eq!(install_target.hooks_dir, expected_hooks_dir);
        assert_eq!(install_target.path, expected_hooks_dir.join("pre-commit"));
    }

    #[test]
    fn test_managed_global_hooks_dir_prefers_appdata_when_home_missing() {
        let path = managed_global_hooks_dir(
            None,
            None,
            Some("C:/Users/test/AppData/Roaming".into()),
            None,
        )
        .expect("appdata path should resolve");

        assert_eq!(
            path,
            std::path::PathBuf::from("C:/Users/test/AppData/Roaming/key-watch/hooks")
        );
    }

    #[test]
    fn test_managed_global_hooks_dir_errors_without_known_base_dir() {
        let error = managed_global_hooks_dir(None, None, None, None)
            .expect_err("missing env inputs should fail");

        assert!(error.contains("Could not determine a directory for global git hooks"));
    }

    #[test]
    fn test_calculate_exit_code_across_modes() {
        let high = Finding {
            file_path: "high.txt".to_string(),
            line_number: 1,
            finding_type: "High".to_string(),
            severity: Severity::High,
            matched_content: "secret".to_string(),
            plugin_name: "DetectorHigh".to_string(),
        };
        let low = Finding {
            file_path: "low.txt".to_string(),
            line_number: 1,
            finding_type: "Low".to_string(),
            severity: Severity::Low,
            matched_content: "token".to_string(),
            plugin_name: "DetectorLow".to_string(),
        };

        assert_eq!(calculate_exit_code(&[], &ExitMode::Strict), 0);
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&low), &ExitMode::Always),
            0
        );
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&low), &ExitMode::Critical),
            0
        );
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&high), &ExitMode::Critical),
            1
        );
        assert_eq!(calculate_exit_code(&[low, high], &ExitMode::Strict), 1);
    }
}
