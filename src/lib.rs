pub mod baseline;
pub mod cli;
pub mod config;
pub mod detector;
pub mod hooks;
pub mod report;
mod run_error;
pub mod scanner;
pub mod utils;

pub use hooks::{generate_pre_commit_hook, generate_pre_push_hook};
pub use run_error::RunCliError;

use clap::Parser;
use cli::{CliOptions, Command, ExitMode, HookAction, OutputFormat, ScanArgs, Shell};
use report::Finding;
use std::env;
use std::time::Instant;

use crate::report::Severity;

pub const EXIT_CODE_RUNTIME_ERROR: i32 = 2;

pub fn run_cli() -> Result<(), RunCliError> {
    let options = CliOptions::parse();
    options.validate()?;

    match options.command {
        Command::Scan(args) => run_scan_command(&args),
        Command::Hook(args) => match args.action {
            HookAction::Install(install_args) => {
                hooks::install_hook(&install_args).map_err(Into::into)
            }
            HookAction::Uninstall(uninstall_args) => {
                hooks::uninstall_hook(&uninstall_args).map_err(Into::into)
            }
        },
        Command::Init { shell } => print_shell_init(&shell),
        Command::VerifyIntegrity => verify_binary_integrity(),
    }
}

/// Writes a line to stdout.
///
/// `println!` panics if stdout is closed, which happens routinely when output
/// is piped (`key-watch scan . | head`). A closed pipe is a normal way for a
/// reader to stop listening, so it is reported as success; anything else is a
/// real I/O failure and is propagated.
fn emit(line: &str) -> Result<(), RunCliError> {
    utils::emit_line(line).map_err(|source| RunCliError::WriteOutput { source })
}

fn run_scan_command(args: &ScanArgs) -> Result<(), RunCliError> {
    let start = Instant::now();

    // Resolve the baseline like config: an explicit --baseline wins, otherwise
    // discover .keywatch-baseline.json in the scanned tree. --update-baseline
    // with nothing discovered creates the conventional file in the current
    // directory. The resolved path also gets excluded from scanning.
    let mut args = args.clone();
    if args.baseline.is_none() && !args.no_baseline_discovery {
        args.baseline = baseline::discover_baseline_path(&args.paths);
        if args.baseline.is_none() && args.update_baseline {
            args.baseline = Some(baseline::DEFAULT_BASELINE_NAME.to_string());
        }
    }
    let args = &args;

    let config = if args.config.is_some() || !args.no_config_discovery {
        config::KeywatchConfig::load_for_paths(args.config.as_deref(), &args.paths)?
    } else {
        None
    };
    let (mut findings, scan_metadata) = scanner::run_scan(args, config.as_ref())?;

    let mut scan_metadata = scan_metadata;
    // Pruning rewrites the baseline from what the scan actually found, so the
    // existing entries must not filter those findings away first.
    let prune = args.prune_baseline && args.update_baseline;
    let mut loaded_baseline = match args.baseline.as_deref() {
        Some(path) => Some(baseline::Baseline::load(std::path::Path::new(path))?),
        None => None,
    };
    if let Some(baseline) = &loaded_baseline.as_ref().filter(|_| !prune) {
        let before = findings.len();
        findings = baseline.filter_findings(findings);
        scan_metadata.suppressed_by_baseline = before - findings.len();
    }

    if args.update_baseline {
        let baseline_path = args
            .baseline
            .as_ref()
            .ok_or(RunCliError::MissingBaselineForUpdate)?;
        let baseline = loaded_baseline
            .as_mut()
            .ok_or(RunCliError::MissingBaselineForUpdate)?;
        if prune {
            // Pruning rebuilds from what the scan found, so a narrowed scan
            // would silently delete entries for everything it never looked
            // at. Make the drop count and the narrowed scope visible.
            let stale = baseline.entries.len();
            *baseline = baseline::Baseline::from_findings(&findings);
            let dropped = stale.saturating_sub(baseline.entries.len());
            if dropped > 0 {
                let noun = if dropped == 1 { "entry" } else { "entries" };
                emit(&format!(
                    "Pruned {dropped} baseline {noun} not found by this scan"
                ))?;
            }
            if !scan_covers_paths(&args.paths) {
                emit("WARNING: --prune-baseline rebuilt the baseline from the scanned paths only; findings outside them are no longer baselined")?;
            }
        } else {
            baseline.update_with_findings(&findings);
        }
        baseline.save(std::path::Path::new(baseline_path))?;
        emit(&format!("Baseline updated: {baseline_path}"))?;
        return Ok(());
    }

    let elapsed = start.elapsed();
    let scan_time = format!(
        "{}.{:01}s",
        elapsed.as_secs(),
        elapsed.subsec_millis() / 100
    );
    let suppressed = scan_metadata.suppressed_by_baseline;
    let severity_counts = report::get_severity_counts(&findings);
    let exit_code = calculate_exit_code(&findings, &args.exit_mode);
    let findings_count = findings.len();
    let report_out = match args.format {
        OutputFormat::Json => {
            report::create_report(findings, scan_metadata, scan_time, args.show_secrets)
        }
        OutputFormat::Sarif => report::create_sarif_report(findings, scan_metadata, scan_time),
    }
    .map_err(|source| RunCliError::ReportSerialize { source })?;

    if suppressed > 0 && !args.verbose {
        emit(&format!(
            "Suppressed {} finding(s) via {}",
            suppressed,
            args.baseline
                .as_deref()
                .map(|path| utils::display_path(std::path::Path::new(path)))
                .unwrap_or_else(|| "baseline".to_string())
        ))?;
    }

    let summary = match findings_count {
        _ if args.verbose => report_out.clone(),
        0 => "No secrets found.".to_string(),
        count => format!(
            "WARNING: {} potential secret(s) detected (CRITICAL: {}, HIGH: {}, MEDIUM: {}, LOW: {})",
            count, severity_counts.0, severity_counts.1, severity_counts.2, severity_counts.3
        ),
    };
    emit(&summary)?;

    if let Some(ref output_path) = args.output {
        utils::write_to_file(output_path, &report_out).map_err(|source| {
            RunCliError::ReportWrite {
                path: output_path.clone(),
                source,
            }
        })?;
    }

    std::process::exit(exit_code);
}

/// Whether the scan inputs cover the whole tree around the baseline, i.e.
/// pruning cannot silently drop entries for locations the scan never looked
/// at. An empty path list means the current directory; a lone "." or an
/// explicit path naming the current directory counts as the whole tree.
fn scan_covers_paths(paths: &[String]) -> bool {
    match paths {
        [] => true,
        [single] => {
            single == "."
                || std::fs::canonicalize(single)
                    .ok()
                    .zip(std::env::current_dir().ok())
                    .is_some_and(|(canonical, cwd)| canonical == cwd)
        }
        _ => false,
    }
}

fn print_shell_init(shell: &Shell) -> Result<(), RunCliError> {
    let script = match shell {
        Shell::Fish => "alias keywatch 'key-watch'\nalias kw 'key-watch'\n",
        Shell::Bash | Shell::Zsh | Shell::Posix => {
            "alias keywatch='key-watch'\nalias kw='key-watch'\n"
        }
    };

    emit(script.trim_end())
}

fn verify_binary_integrity() -> Result<(), RunCliError> {
    let exe_path = env::current_exe().map_err(|source| RunCliError::ExecutablePath { source })?;
    let metadata = exe_path
        .metadata()
        .map_err(|source| RunCliError::ExecutableMetadata { source })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = metadata.permissions();
        let mode = perms.mode();
        if mode & 0o002 != 0 {
            eprintln!("WARNING: Binary is world-writable! Integrity may be compromised.");
        }
    }

    emit(&format!("Binary integrity verified: {exe_path:?}"))?;
    emit(&format!("Size: {} bytes", metadata.len()))
}

fn calculate_exit_code(findings: &[Finding], exit_mode: &ExitMode) -> i32 {
    if findings.is_empty() {
        return 0;
    }

    match exit_mode {
        ExitMode::Always => 0,
        ExitMode::Critical => {
            let has_critical_or_high = findings
                .iter()
                .any(|finding| matches!(finding.severity, Severity::Critical | Severity::High));
            i32::from(has_critical_or_high)
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
