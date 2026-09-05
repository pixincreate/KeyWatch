//! The false-positive corpus: common content shapes that secret scanners
//! are traditionally noisy on. Scanned end to end; the expected findings
//! are exactly the two residuals that cannot be separated from real
//! secrets by shape (a company-domain email and a bare npm integrity
//! value). Any new finding here is a regression in detector precision.

use key_watch::cli::ScanArgs;
use key_watch::scanner::run_scan;
use std::path::PathBuf;

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fp_corpus")
}

fn scan_corpus() -> Vec<key_watch::report::Finding> {
    let options = ScanArgs {
        paths: vec![corpus_path().to_string_lossy().into_owned()],
        no_baseline_discovery: true,
        ..Default::default()
    };
    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    findings
}

#[test]
fn test_fp_corpus_produces_exactly_the_documented_residuals() {
    let findings = scan_corpus();

    assert_eq!(findings.len(), 2, "unexpected findings: {findings:#?}");

    let email = findings
        .iter()
        .find(|f| f.finding_type == "Email Address")
        .expect("the company-domain email is the documented residual");
    assert!(
        email.file_path.ends_with("README.md"),
        "unexpected email location: {}",
        email.file_path
    );

    let base64 = findings
        .iter()
        .find(|f| f.finding_type == "Base64 Encoded String")
        .expect("the npm integrity value is the documented residual");
    assert!(
        base64.file_path.ends_with("package.json"),
        "unexpected base64 location: {}",
        base64.file_path
    );
}

#[test]
fn test_fp_corpus_documentation_examples_are_never_reported() {
    let findings = scan_corpus();
    let reported_types: Vec<_> = findings.iter().map(|f| f.finding_type.as_str()).collect();

    for finding_type in [
        "AWS Access Key",
        "Password",
        "Generic Key/Secret",
        "Phone Number",
        "Aadhaar Card Number",
        "Random String",
    ] {
        assert!(
            !reported_types.contains(&finding_type),
            "{finding_type} must never fire on the FP corpus, got {reported_types:?}"
        );
    }
}
