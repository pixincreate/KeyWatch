pub mod cli;
pub mod detector;
pub mod hooks;
pub mod report;
pub mod scanner;
pub mod utils;

use clap::Parser;
use cli::CliOptions;
use report::Finding;
use std::env;
use std::time::Instant;

pub use hooks::{generate_pre_commit_hook, generate_pre_push_hook};

const EXIT_MODE_ALWAYS: &str = "always";
const EXIT_MODE_CRITICAL: &str = "critical";
const EXIT_MODE_STRICT: &str = "strict";
const SEVERITY_HIGH: &str = "HIGH";
pub const EXIT_CODE_RUNTIME_ERROR: i32 = 2;

pub fn run_cli() -> Result<(), String> {
    let options = CliOptions::parse();
    let start = Instant::now();

    if let Some(hook_type) = &options.install_hook {
        install_hook(hook_type, &options)?;
        return Ok(());
    }

    if options.verify_integrity {
        verify_binary_integrity()?;
    }

    let (findings, scan_metadata) = scanner::run_scan(&options)?;
    let elapsed = start.elapsed();
    let scan_time = format!(
        "{}.{:01}s",
        elapsed.as_secs(),
        elapsed.subsec_millis() / 100
    );
    let severity_counts = report::get_severity_counts(&findings);
    let exit_code = calculate_exit_code(&findings, &options.exit_mode);
    let findings_count = findings.len();
    let report_json = report::create_report(findings, scan_metadata, scan_time)
        .map_err(|err| format!("Failed to serialize report: {}", err))?;

    if options.verbose {
        println!("{report_json}");
    } else if findings_count == 0 {
        println!("No secrets found.");
    } else {
        println!(
            "WARNING: {} potential secret(s) detected (HIGH: {}, MEDIUM: {}, LOW: {})",
            findings_count, severity_counts.0, severity_counts.1, severity_counts.2
        );
    }

    if let Some(ref output_path) = options.output {
        utils::write_to_file(output_path, &report_json)
            .map_err(|err| format!("Failed to write report to '{}': {}", output_path, err))?;
    }

    std::process::exit(exit_code);
}

fn install_hook(hook_type: &str, options: &CliOptions) -> Result<(), String> {
    let hook_content = match hook_type {
        "pre-push" => hooks::generate_pre_push_hook(options),
        "pre-commit" => hooks::generate_pre_commit_hook(options),
        _ => {
            return Err(format!("Unknown hook type: {}", hook_type));
        }
    };

    let hook_path = format!(".git/hooks/{hook_type}");
    utils::write_to_file(&hook_path, &hook_content)
        .map_err(|err| format!("Failed to install hook '{}': {}", hook_type, err))?;
    utils::make_executable(&hook_path)
        .map_err(|err| format!("Failed to make hook executable '{}': {}", hook_path, err))?;

    println!("Installed {hook_type} hook at {hook_path}");
    println!(
        "The hook will run automatically during git {}.",
        hook_type.replace('-', " ")
    );
    Ok(())
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

fn calculate_exit_code(findings: &[Finding], exit_mode: &str) -> i32 {
    if findings.is_empty() {
        return 0;
    }

    match exit_mode {
        EXIT_MODE_ALWAYS => 0,
        EXIT_MODE_CRITICAL => {
            let has_high = findings
                .iter()
                .any(|finding| finding.severity == SEVERITY_HIGH);
            if has_high { 1 } else { 0 }
        }
        EXIT_MODE_STRICT => 1,
        _ => 1,
    }
}
