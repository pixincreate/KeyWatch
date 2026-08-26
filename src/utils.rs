use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// The user's home directory.
static HOME_DIR: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
});

/// Writes a line to stdout.
///
/// `println!` panics if stdout is closed, which happens routinely when output
/// is piped (`key-watch hook install | head`). A closed pipe is a normal way
/// for a reader to stop listening, so it is reported as success.
pub fn emit_line(line: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{line}") {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Renders a path for terminal output, abbreviating the home directory as `~`.
pub fn display_path(path: &Path) -> String {
    match HOME_DIR
        .as_deref()
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

use std::io::{Result, Write};

/// Writes a report file readable only by its owner.
///
/// `File::create` uses 0666 & ~umask, i.e. world-readable by default, and a
/// report can carry matched text when `--show-secrets` is set.
pub fn write_to_file(path: &str, content: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(unix)]
pub fn make_executable(path: &str) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
pub fn make_executable(_path: &str) -> Result<()> {
    Ok(())
}
