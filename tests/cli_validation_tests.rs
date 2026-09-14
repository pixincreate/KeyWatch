use key_watch::RunCliError;
use key_watch::cli::{CliValidationError, ScanArgs};

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

#[test]
fn test_rev_range_rejects_flag_shaped_values() {
    // The range lands on the git command line; a leading dash would be
    // parsed by git as a flag (argument injection).
    let options = ScanArgs {
        git_history: true,
        rev_range: Some("--exec=evil".to_string()),
        ..Default::default()
    };

    let error = options
        .validate()
        .expect_err("flag-shaped rev-range must be rejected");
    assert_eq!(
        error,
        CliValidationError::RevRangeLooksLikeFlag {
            range: "--exec=evil".to_string()
        }
    );
}

#[test]
fn test_rev_range_accepts_sha_ranges() {
    let options = ScanArgs {
        git_history: true,
        rev_range: Some("abc123..def456".to_string()),
        ..Default::default()
    };

    assert!(options.validate().is_ok());
}
