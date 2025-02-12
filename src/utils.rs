use std::fs::File;
use std::io::{Result, Write};

/// write_to_file writes the given content to a file at the specified path.
pub fn write_to_file(path: &str, content: &str) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
