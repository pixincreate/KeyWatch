mod cli;
mod detector;
mod hooks;
mod report;
mod scanner;
mod utils;

use clap::Parser;
use cli::CliOptions;
use hooks::{generate_pre_commit_hook, generate_pre_push_hook};
use report::{create_report, Finding, ScanMetadata};
use scanner::run_scan;
use std::env;
use std::time::Instant;

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = CliOptions::parse();
    let start = Instant::now();

    if let Some(hook_type) = &options.install_hook {
        install_hook(hook_type, &options)?;
        return Ok(());
    }

    if options.verify_integrity {
        verify_binary_integrity()?;
    }

    let (findings, scan_metadata) = run_scan(&options)?;
    let elapsed = start.elapsed();
    let scan_time = format!(
        "{}.{:01}s",
        elapsed.as_secs(),
        elapsed.subsec_millis() / 100
    );
    let report_json = report::create_report(findings.clone(), scan_metadata, scan_time)
        .map_err(|err| format!("Failed to serialize report: {}", err))?;

    if options.verbose {
        println!("{report_json}");
    }

    if let Some(ref output_path) = options.output {
        utils::write_to_file(output_path, &report_json)
            .map_err(|err| format!("Failed to write report to '{}': {}", output_path, err))?;
    }

    let exit_code = calculate_exit_code(&findings, &options.exit_mode);
    std::process::exit(exit_code);
}

fn install_hook(hook_type: &str, options: &CliOptions) -> Result<(), String> {
    let hook_content = match hook_type {
        "pre-push" => generate_pre_push_hook(options),
        "pre-commit" => generate_pre_commit_hook(options),
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
        "always" => 0,
        "critical" => {
            // Exit 0 if only LOW/MEDIUM severity
            let has_high = findings.iter().any(|f| f.severity == "HIGH");
            if has_high {
                1
            } else {
                0
            }
        }
        _ => 1, // strict - exit non-zero for any finding
    }
}
