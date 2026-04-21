use std::fs::File;
use std::io::{Result, Write};

/// write_to_file writes the given content to a file at the specified path.
pub fn write_to_file(path: &str, content: &str) -> Result<()> {
    let mut file = File::create(path)?;
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
