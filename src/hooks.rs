use crate::cli::{HookInstallArgs, HookUninstallArgs};
use crate::utils;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

mod error;
pub use error::HookError;

const PRE_PUSH_TEMPLATE: &str = include_str!("../templates/pre-push.sh");
const PRE_COMMIT_TEMPLATE: &str = include_str!("../templates/pre-commit.sh");

const DEFAULT_BINARY_NAME: &str = "key-watch";

const KEYWATCH_MARKER: &str = "# Installed by KeyWatch";

fn shell_escape(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

/// Renders a path for terminal output, abbreviating the home directory as `~`.
fn display_path(path: &Path) -> String {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    match home
        .as_deref()
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

fn build_repo_section(allowed: Option<&str>, blocked: Option<&str>) -> String {
    let escaped_allowed = allowed.map(shell_escape);
    let escaped_blocked = blocked.map(shell_escape);

    if escaped_allowed.is_none() && escaped_blocked.is_none() {
        return String::new();
    }

    let allowed_line = escaped_allowed.map_or(String::new(), |escaped| {
        format!("ALLOWED_REPOS={}\n", escaped)
    });
    let blocked_line = escaped_blocked.map_or(String::new(), |escaped| {
        format!("BLOCKED_REPOS={}\n", escaped)
    });
    format!("{}{}", allowed_line, blocked_line)
}

fn render_pre_push(args: &HookInstallArgs) -> String {
    let binary_name = shell_escape(&hook_binary_name());
    let repo_section =
        build_repo_section(args.allowed_repos.as_deref(), args.blocked_repos.as_deref());

    PRE_PUSH_TEMPLATE
        .replace("{{binary_name}}", &binary_name)
        .replace("{{repo_section}}", &repo_section)
}

fn render_pre_commit(args: &HookInstallArgs) -> String {
    let binary_name = shell_escape(&hook_binary_name());
    let exclude_patterns = args
        .exclude
        .as_deref()
        .map(shell_escape)
        .unwrap_or_default();

    PRE_COMMIT_TEMPLATE
        .replace("{{binary_name}}", &binary_name)
        .replace("{{exclude_patterns}}", &exclude_patterns)
}

pub fn generate_pre_push_hook(args: &HookInstallArgs) -> String {
    render_pre_push(args)
}

pub fn generate_pre_commit_hook(args: &HookInstallArgs) -> String {
    render_pre_commit(args)
}

fn hook_binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| DEFAULT_BINARY_NAME.to_string())
}

/// Install a git hook of the given type.
///
/// Writes the rendered hook script to the resolved target path and makes it
/// executable. For global installs, a managed hooks directory is created and
/// configured via `git config --global core.hooksPath` if none is set.
pub fn install_hook(args: &HookInstallArgs) -> Result<(), HookError> {
    let hook_content = match args.hook_type {
        crate::cli::HookType::PrePush => generate_pre_push_hook(args),
        crate::cli::HookType::PreCommit => generate_pre_commit_hook(args),
    };
    let hook_type_str = args.hook_type.as_str();

    let install_target = resolve_hook_install_target(hook_type_str, args.global)?;

    if !install_target.is_global {
        ensure_local_hook_target_is_safe_to_create(&install_target.path)?;
    }

    if let Some(parent) = install_target.path.parent() {
        fs::create_dir_all(parent).map_err(|source| HookError::CreateHookDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    if install_target.is_global {
        ensure_global_hook_target_is_safe(&install_target.path)?;
    }

    let hook_path = install_target.path.to_string_lossy().into_owned();
    utils::write_to_file(&hook_path, &hook_content).map_err(|source| HookError::InstallHook {
        path: PathBuf::from(&hook_path),
        source,
    })?;
    utils::make_executable(&hook_path).map_err(|source| HookError::MakeHookExecutable {
        path: PathBuf::from(&hook_path),
        source,
    })?;

    if install_target.configured_global_path {
        println!(
            "Configured git --global core.hooksPath to {}",
            display_path(&install_target.hooks_dir)
        );
    }

    let scope = if install_target.is_global {
        "global "
    } else {
        ""
    };
    println!(
        "Installed {scope}{hook_type_str} hook at {}",
        display_path(&install_target.path)
    );
    println!(
        "The hook will run automatically during git {}.",
        hook_type_str.replace('-', " ")
    );

    Ok(())
}

/// Uninstall a git hook of the given type.
///
/// Only removes hooks that KeyWatch previously installed (verified via the
/// marker comment). Missing hooks are reported as a no-op success.
pub fn uninstall_hook(args: &HookUninstallArgs) -> Result<(), HookError> {
    let hook_type_str = args.hook_type.as_str();
    let install_target = resolve_hook_uninstall_target(hook_type_str, args.global)?;

    let scope = if install_target.is_global {
        "global"
    } else {
        "local"
    };
    if !install_target.path.exists() {
        println!(
            "No {scope} {hook_type_str} hook found at {}",
            display_path(&install_target.path)
        );
        return Ok(());
    }

    ensure_hook_target_is_keywatch_managed(
        &install_target.path,
        install_target.is_global,
        "remove",
    )?;

    fs::remove_file(&install_target.path).map_err(|source| HookError::RemoveHook {
        path: install_target.path.clone(),
        source,
    })?;

    println!(
        "Removed {scope} {hook_type_str} hook at {}",
        display_path(&install_target.path)
    );

    Ok(())
}

struct HookInstallTarget {
    path: PathBuf,
    hooks_dir: PathBuf,
    is_global: bool,
    configured_global_path: bool,
}

impl HookInstallTarget {
    fn local(hook_type: &'static str) -> Result<Self, HookError> {
        let hooks_dir = resolve_local_hooks_dir()?;
        Ok(Self {
            path: hooks_dir.join(hook_type),
            hooks_dir,
            is_global: false,
            configured_global_path: false,
        })
    }

    fn global(hook_type: &'static str) -> Result<Self, HookError> {
        if let Some(hooks_dir) = read_global_hooks_path()? {
            return Ok(Self {
                path: hooks_dir.join(hook_type),
                hooks_dir,
                is_global: true,
                configured_global_path: false,
            });
        }

        let managed_dir = managed_global_hooks_dir(
            env::var_os("XDG_CONFIG_HOME"),
            env::var_os("HOME"),
            env::var_os("APPDATA"),
            env::var_os("USERPROFILE"),
        )?;

        fs::create_dir_all(&managed_dir).map_err(|source| {
            HookError::CreateGlobalHooksDirectory {
                path: managed_dir.clone(),
                source,
            }
        })?;
        configure_global_hooks_path(&managed_dir)?;

        Ok(Self {
            path: managed_dir.join(hook_type),
            hooks_dir: managed_dir,
            is_global: true,
            configured_global_path: true,
        })
    }
}

fn resolve_hook_install_target(
    hook_type: &'static str,
    global: bool,
) -> Result<HookInstallTarget, HookError> {
    if global {
        HookInstallTarget::global(hook_type)
    } else {
        HookInstallTarget::local(hook_type)
    }
}

fn resolve_hook_uninstall_target(
    hook_type: &'static str,
    global: bool,
) -> Result<HookInstallTarget, HookError> {
    if !global {
        return HookInstallTarget::local(hook_type);
    }

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
}

fn resolve_local_hooks_dir() -> Result<PathBuf, HookError> {
    resolve_local_hooks_dir_from(Path::new("."))
}

fn resolve_local_hooks_dir_from(cwd: &Path) -> Result<PathBuf, HookError> {
    let output = ProcessCommand::new("git")
        .current_dir(cwd)
        .args(["rev-parse", "--path-format=absolute", "--git-path", "hooks"])
        .output()
        .map_err(|source| HookError::ResolveGitHooksDirectory { source })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            HookError::MissingLocalRepository
        } else {
            HookError::ResolveGitHooksDirectoryFromGit { stderr }
        });
    }

    let hooks_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hooks_path.is_empty() {
        return Err(HookError::EmptyGitHooksDirectory);
    }

    Ok(PathBuf::from(hooks_path))
}

fn read_global_hooks_path() -> Result<Option<PathBuf>, HookError> {
    let output = ProcessCommand::new("git")
        .args(["config", "--global", "--path", "--get", "core.hooksPath"])
        .output()
        .map_err(|source| HookError::ReadGlobalHooksPath { source })?;

    match output.status.code() {
        _ if output.status.success() => {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok((!value.is_empty()).then(|| PathBuf::from(value)))
        }
        // Exit code 1 means the key is not set.
        Some(1) => Ok(None),
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(HookError::ReadGlobalHooksPathFromGit { stderr })
        }
    }
}

fn managed_global_hooks_dir(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
    appdata: Option<std::ffi::OsString>,
    userprofile: Option<std::ffi::OsString>,
) -> Result<PathBuf, HookError> {
    xdg_config_home
        .map(|xdg| PathBuf::from(xdg).join("key-watch").join("hooks"))
        .or_else(|| {
            home.map(|home| {
                PathBuf::from(home)
                    .join(".config")
                    .join("key-watch")
                    .join("hooks")
            })
        })
        .or_else(|| Some(PathBuf::from(appdata?).join("key-watch").join("hooks")))
        .or_else(|| {
            userprofile.map(|profile| {
                PathBuf::from(profile)
                    .join(".config")
                    .join("key-watch")
                    .join("hooks")
            })
        })
        .ok_or(HookError::MissingGlobalHooksBaseDir)
}

fn configure_global_hooks_path(hooks_dir: &Path) -> Result<(), HookError> {
    let output = ProcessCommand::new("git")
        .args(["config", "--global", "core.hooksPath"])
        .arg(hooks_dir)
        .output()
        .map_err(|source| HookError::ConfigureGlobalHooksPath { source })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(HookError::ConfigureGlobalHooksPathWithGit {
            hooks_dir: hooks_dir.to_path_buf(),
            stderr,
        })
    }
}

fn ensure_global_hook_target_is_safe(hook_path: &Path) -> Result<(), HookError> {
    ensure_hook_target_is_keywatch_managed(hook_path, true, "overwrite")
}

fn ensure_local_hook_target_is_safe_to_create(hook_path: &Path) -> Result<(), HookError> {
    resolve_local_hooks_dir()?;
    if hook_path.exists() {
        ensure_hook_target_is_keywatch_managed(hook_path, false, "overwrite")?;
    }
    Ok(())
}

/// Refuse to touch an existing hook unless KeyWatch installed it.
fn ensure_hook_target_is_keywatch_managed(
    hook_path: &Path,
    is_global: bool,
    action: &'static str,
) -> Result<(), HookError> {
    if !hook_path.exists() {
        return Ok(());
    }

    let content =
        fs::read_to_string(hook_path).map_err(|source| HookError::InspectExistingHook {
            path: hook_path.to_path_buf(),
            source,
        })?;

    if content.contains(KEYWATCH_MARKER) {
        return Ok(());
    }

    let scope = if is_global { "global" } else { "local" };
    Err(HookError::RefuseExistingHook {
        action,
        scope,
        path: hook_path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        HookError, ensure_global_hook_target_is_safe, ensure_local_hook_target_is_safe_to_create,
        managed_global_hooks_dir, resolve_hook_uninstall_target, resolve_local_hooks_dir_from,
    };
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
        // Pin the local hooks path so a machine-wide core.hooksPath does not
        // redirect hook resolution away from this repository.
        let status = Command::new("git")
            .args(["config", "core.hooksPath", ".git/hooks"])
            .current_dir(path)
            .status()
            .expect("run git config");
        assert!(status.success(), "git config should succeed");
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
        assert!(
            error
                .to_string()
                .contains("Refusing to overwrite existing global hook")
        );

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
        assert!(
            error
                .to_string()
                .contains("Refusing to overwrite existing local hook")
        );

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

        assert!(matches!(error, HookError::MissingGlobalHooksBaseDir));
        assert_eq!(
            error.to_string(),
            "Could not determine a directory for global git hooks"
        );
    }
}
