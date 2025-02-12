use clap::{ArgGroup, Parser};

/// KeyWatch: A secret scanner for your files and directories.
#[derive(Parser, Debug)]
#[command(author, version, about = "Scan files and directories for secrets", long_about = None)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(&["file", "dir"]),
))]
pub struct CliOptions {
    /// Scan a single file
    #[arg(short, long)]
    pub file: Option<String>,

    /// Scan all files in a directory (scans recursively)
    #[arg(short, long)]
    pub dir: Option<String>,

    /// Output the result to a file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Print the scan results to the console
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}
