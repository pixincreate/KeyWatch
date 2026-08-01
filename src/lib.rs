pub mod baseline;
pub mod cli;
pub mod config;
pub mod detector;
pub mod hooks;
pub mod report;
pub mod scanner;
pub mod utils;

pub use hooks::{generate_pre_commit_hook, generate_pre_push_hook};

use clap::Parser;
use cli::{CliOptions, Command, ExitMode, HookAction, OutputFormat, ScanArgs, Shell};
use report::Finding;
use std::env;
use std::time::Instant;

use crate::report::Severity;

pub const EXIT_CODE_RUNTIME_ERROR: i32 = 2;

pub fn run_cli() -> Result<(), String> {
    let options = CliOptions::parse();
    options.validate()?;

    match options.command {
        Command::Scan(args) => run_scan_command(&args),
        Command::Hook(args) => match args.action {
            HookAction::Install(install_args) => hooks::install_hook(&install_args),
            HookAction::Uninstall(uninstall_args) => hooks::uninstall_hook(&uninstall_args),
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

    let config = if args.config.is_some() || !args.no_config_discovery {
        config::KeywatchConfig::load_for_paths(args.config.as_deref(), &args.paths)?
    } else {
        None
    };
    let (mut findings, scan_metadata) = scanner::run_scan(args, config.as_ref())?;

    if let Some(ref baseline_path) = args.baseline {
        let baseline = baseline::Baseline::load(std::path::Path::new(baseline_path))?;
        findings = baseline.filter_findings(findings);
    }

    if args.update_baseline {
        let baseline_path = args
            .baseline
            .as_ref()
            .ok_or("--update-baseline requires --baseline <path>")?;
        let mut baseline = baseline::Baseline::load(std::path::Path::new(baseline_path))?;
        baseline.update_with_findings(&findings);
        baseline.save(std::path::Path::new(baseline_path))?;
        println!("Baseline updated: {}", baseline_path);
        return Ok(());
    }

    let elapsed = start.elapsed();
    let scan_time = format!(
        "{}.{:01}s",
        elapsed.as_secs(),
        elapsed.subsec_millis() / 100
    );
    let severity_counts = report::get_severity_counts(&findings);
    let exit_code = calculate_exit_code(&findings, &args.exit_mode);
    let findings_count = findings.len();
    let report_out = match args.format {
        OutputFormat::Json => report::create_report(findings, scan_metadata, scan_time),
        OutputFormat::Sarif => report::create_sarif_report(findings, scan_metadata, scan_time),
    }
    .map_err(|err| format!("Failed to serialize report: {}", err))?;

    if args.verbose {
        println!("{report_out}");
    } else if findings_count == 0 {
        println!("No secrets found.");
    } else {
        println!(
            "WARNING: {} potential secret(s) detected (CRITICAL: {}, HIGH: {}, MEDIUM: {}, LOW: {})",
            findings_count,
            severity_counts.0,
            severity_counts.1,
            severity_counts.2,
            severity_counts.3
        );
    }

    if let Some(ref output_path) = args.output {
        utils::write_to_file(output_path, &report_out)
            .map_err(|err| format!("Failed to write report to '{}': {}", output_path, err))?;
    }

    std::process::exit(exit_code);
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
            let has_critical_or_high = findings.iter().any(|finding| {
                finding.severity == Severity::Critical || finding.severity == Severity::High
            });
            if has_critical_or_high { 1 } else { 0 }
        }
        ExitMode::Strict => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{Severity, calculate_exit_code};
    use crate::cli::ExitMode;
    use crate::report::Finding;

    #[test]
    fn test_calculate_exit_code_across_modes() {
        let critical = Finding {
            file_path: "critical.txt".to_string(),
            line_number: 1,
            finding_type: "Critical".to_string(),
            severity: Severity::Critical,
            matched_content: "secret".to_string(),
            plugin_name: "DetectorCritical".to_string(),
        };
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
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&critical), &ExitMode::Critical),
            1
        );
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&critical), &ExitMode::Always),
            0
        );
        assert_eq!(
            calculate_exit_code(&[low.clone(), high], &ExitMode::Strict),
            1
        );
        assert_eq!(
            calculate_exit_code(&[low.clone(), critical], &ExitMode::Strict),
            1
        );
    }
}
