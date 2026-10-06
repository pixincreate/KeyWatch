use std::io::{Result, Write};
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
    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{line}") {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// The user's home directory: `$HOME`, falling back to `$USERPROFILE` (the
/// Windows convention). Callers with platform-specific fallback orders
/// (hooks resolve XDG/APPDATA first) resolve their own.
pub fn home_dir() -> Option<&'static PathBuf> {
    HOME_DIR.as_ref()
}

/// Whether `path` is writable by every user.
///
/// A world-writable directory or file is not a trust boundary: on a shared
/// host any user can replace configuration that a scan is about to trust.
#[cfg(unix)]
pub fn is_world_writable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o002 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn is_world_writable(_path: &Path) -> bool {
    false
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

/// Atomically replaces a file with an owner-readable report.
pub fn write_to_file(path: &str, content: &str) -> Result<()> {
    atomic_write(Path::new(path), content.as_bytes())
}

/// Uses a same-directory temporary file. The caller must control the parent
/// directory and its ancestors; this is not protection against ancestor races.
pub(crate) fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    use std::fs;
    use std::io::{Error, ErrorKind};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if fs::symlink_metadata(parent)?.file_type().is_symlink() || is_world_writable(parent) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Output parent must be a trusted directory",
        ));
    }
    let check_destination = || -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_file() => Err(Error::new(
                ErrorKind::InvalidInput,
                "Output destination must be a regular file, not a symlink",
            )),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    };
    check_destination()?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    for _ in 0..128 {
        let temporary = parent.join(format!(
            ".keywatch-write-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        if temporary.file_name() == path.file_name() {
            continue;
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(content)?;
            file.sync_all()?;
            drop(file);
            check_destination()?;
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    Err(Error::new(
        ErrorKind::AlreadyExists,
        "Cannot reserve an output temporary file",
    ))
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

/// Decodes standard-alphabet base64 (`+/`, optional `=` padding). Returns
/// `None` for any character outside the alphabet so arbitrary text is
/// rejected cheaply. Used to scan the decoded form of base64 runs found in
/// scanned lines.
pub(crate) fn decode_base64_standard(input: &str) -> Option<Vec<u8>> {
    const fn value_of(byte: u8) -> i8 {
        match byte {
            b'A'..=b'Z' => (byte - b'A') as i8,
            b'a'..=b'z' => (byte - b'a' + 26) as i8,
            b'0'..=b'9' => (byte - b'0' + 52) as i8,
            b'+' => 62,
            b'/' => 63,
            _ => -1,
        }
    }

    let mut decoded = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input.bytes() {
        if byte == b'=' {
            continue;
        }
        let value = value_of(byte);
        if value < 0 {
            return None;
        }
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(decoded)
}
