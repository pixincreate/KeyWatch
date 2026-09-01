use key_watch::RunCliError;
use key_watch::cli::{CliValidationError, ExitMode, OutputFormat, ScanArgs};

#[test]
fn test_stdin_with_path_validation_returns_typed_error() {
    let options = ScanArgs {
        paths: vec!["secret.txt".to_string()],
        stdin: true,
        no_baseline_discovery: true,
        ..Default::default()
    };

    let error = options
        .validate()
        .expect_err("stdin with paths should be rejected");

    assert_eq!(error, CliValidationError::StdinWithPaths);
    assert_eq!(error.to_string(), "Cannot specify both --stdin and paths");
}

#[test]
fn test_run_cli_error_wraps_cli_validation_display() {
    let error = RunCliError::from(CliValidationError::StdinWithPaths);

    assert_eq!(error.to_string(), "Cannot specify both --stdin and paths");
}

#[test]
fn test_staged_with_stdin_validation_returns_typed_error() {
    let options = ScanArgs {
        stdin: true,
        staged: true,
        no_baseline_discovery: true,
        ..Default::default()
    };

    let error = options
        .validate()
        .expect_err("staged with stdin should be rejected");

    assert_eq!(error, CliValidationError::StagedWithStdin);
    assert_eq!(
        error.to_string(),
        "Cannot specify both --staged and --stdin"
    );
}

#[test]
fn test_staged_with_git_history_validation_returns_typed_error() {
    let options = ScanArgs {
        git_history: true,
        staged: true,
        no_baseline_discovery: true,
        ..Default::default()
    };

    let error = options
        .validate()
        .expect_err("staged with git-history should be rejected");

    assert_eq!(error, CliValidationError::StagedWithGitHistory);
    assert_eq!(
        error.to_string(),
        "Cannot specify both --staged and --git-history"
    );
}

#[test]
fn test_staged_allows_zero_or_many_paths() {
    let options = ScanArgs {
        paths: vec!["a.txt".to_string(), "b.txt".to_string()],
        staged: true,
        no_baseline_discovery: true,
        ..Default::default()
    };

    assert!(options.validate().is_ok(), "staged paths narrow the diff");
}
