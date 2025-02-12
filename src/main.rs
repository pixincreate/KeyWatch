mod cli;
mod detector;
mod report;
mod scanner;
mod utils;

use clap::Parser;
use cli::CliOptions;
use scanner::run_scan;
use std::time::Instant;

fn main() {
    let options = CliOptions::parse();
    let start = Instant::now();
    let (findings, scan_metadata) = run_scan(&options);
    let elapsed = start.elapsed();
    let scan_time = format!(
        "{}.{:01}s",
        elapsed.as_secs(),
        elapsed.subsec_millis() / 100
    );
    let report_json = report::create_report(findings, scan_metadata, scan_time);
    if options.verbose {
        println!("{}", report_json);
    }
    if let Some(ref output_path) = options.output {
        if let Err(e) = utils::write_to_file(output_path, &report_json) {
            eprintln!("Error writing to file {}: {}", output_path, e);
        }
    }
}
