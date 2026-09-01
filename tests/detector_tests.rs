use key_watch::detector::{Detector, DetectorError, DetectorInitError};
use key_watch::report::Severity;
use std::str::FromStr;

#[test]
fn test_allowlist_suppresses_matched_content() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[r"secret_allowed".to_string()],
        &[],
        None,
    )?;

    assert!(detector.regex.is_match("secret_here"));
    assert!(
        detector
            .allowlist
            .iter()
            .any(|p| p.is_match("secret_allowed")),
        "Allowlist should match 'secret_allowed'"
    );
    assert!(
        !detector
            .allowlist
            .iter()
            .any(|p| p.is_match("secret_blocked")),
        "Allowlist should not match 'secret_blocked'"
    );
    Ok(())
}

#[test]
fn test_detector_without_allowlist_allows_all() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        None,
    )?;

    assert!(detector.allowlist.is_empty());
    assert!(detector.regex.is_match("secret_anything"));
    Ok(())
}

#[test]
fn test_invalid_allowlist_pattern_returns_error() {
    let result = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[r"[invalid".to_string()],
        &[],
        None,
    );
    assert!(
        result.is_err(),
        "Invalid allowlist pattern should return error"
    );
}

#[test]
fn test_keywords_prefilter_skips_non_matching_content() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &["apikey".to_string()],
        None,
    )?;

    assert!(!detector.has_keywords("some random text without the keyword"));
    assert!(detector.has_keywords("this text contains apikey in it"));
    Ok(())
}

#[test]
fn test_keywords_are_lowercased_at_construction() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &["ApiKey".to_string()],
        None,
    )?;

    // Callers lowercase content once per line; uppercase keyword definitions
    // must still match that lowered content.
    assert!(detector.has_keywords("this text contains apikey in it"));
    Ok(())
}

#[test]
fn test_empty_keywords_allows_all_content() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        None,
    )?;

    assert!(detector.has_keywords("any content should pass"));
    assert!(detector.has_keywords(""));
    Ok(())
}

#[test]
fn test_entropy_filters_low_entropy_matches() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        Some(3.0),
    )?;

    assert!(
        !detector.has_sufficient_entropy("secret_aaaaaaaa"),
        "Low entropy string should be rejected"
    );
    assert!(
        detector.has_sufficient_entropy("secret_a1B2c3D4e5"),
        "High entropy string should pass"
    );
    Ok(())
}

#[test]
fn test_no_entropy_threshold_allows_all() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        None,
    )?;

    assert!(detector.has_sufficient_entropy("secret_aaaaaaaa"));
    assert!(detector.has_sufficient_entropy("secret_a1B2c3D4e5"));
    Ok(())
}

#[test]
fn test_severity_from_str_valid_variants() {
    assert_eq!(Severity::from_str("CRITICAL").unwrap(), Severity::Critical);
    assert_eq!(Severity::from_str("HIGH").unwrap(), Severity::High);
    assert_eq!(Severity::from_str("MEDIUM").unwrap(), Severity::Medium);
    assert_eq!(Severity::from_str("LOW").unwrap(), Severity::Low);
    assert_eq!(Severity::from_str("critical").unwrap(), Severity::Critical);
    assert_eq!(Severity::from_str("  High  ").unwrap(), Severity::High);
}

#[test]
fn test_severity_from_str_invalid_returns_error() {
    let err = Severity::from_str("UNKNOWN").unwrap_err();
    assert!(
        err.to_string().contains("UNKNOWN"),
        "Error message should include the offending input"
    );
    assert!(Severity::from_str("").is_err());
    assert!(Severity::from_str("warn").is_err());
}

#[test]
fn test_severity_as_str_canonical_uppercase() {
    assert_eq!(Severity::Critical.as_str(), "CRITICAL");
    assert_eq!(Severity::High.as_str(), "HIGH");
    assert_eq!(Severity::Medium.as_str(), "MEDIUM");
    assert_eq!(Severity::Low.as_str(), "LOW");
}

#[test]
fn test_detector_new_invalid_severity_returns_typed_error() {
    let result = Detector::new(
        "BadSevDetector",
        r"\btest\b",
        "Test",
        "BOGUS",
        &[],
        &[],
        None,
    );
    match result {
        Err(DetectorError::InvalidSeverity { detector, source }) => {
            assert_eq!(detector, "BadSevDetector");
            assert!(source.to_string().contains("BOGUS"));
        }
        _ => panic!("expected InvalidSeverity error variant"),
    }
}

#[test]
fn test_detector_new_stores_parsed_severity() -> Result<(), DetectorError> {
    let detector = Detector::new("SevDetector", r"\btest\b", "Test", "MEDIUM", &[], &[], None)?;
    assert_eq!(detector.severity, Severity::Medium);
    Ok(())
}

#[test]
fn test_initialize_detectors_all_names_unique() {
    let detectors = key_watch::detector::initialize_detectors()
        .expect("detectors.toml should load without error");
    let mut names = std::collections::HashSet::new();
    for det in &detectors {
        assert!(
            names.insert(det.name.as_str()),
            "duplicate detector name: {}",
            det.name
        );
    }
}

#[test]
fn test_detector_init_error_duplicate_name_display() {
    let error = DetectorInitError::DuplicateName {
        detector: "Dup".to_string(),
    };

    assert_eq!(error.to_string(), "duplicate detector name 'Dup'");
}

#[test]
fn test_generic_key_value_ignores_unquoted_identifier_assignments() {
    let detectors = key_watch::detector::initialize_detectors().expect("load detectors");
    let generic = detectors
        .iter()
        .find(|d| d.name == "GenericKeyValueDetector")
        .expect("GenericKeyValueDetector should exist");

    let is_reported = |line: &str| {
        generic.regex.find_iter(line).any(|m| {
            !generic.allowlist.iter().any(|a| a.is_match(m.as_str()))
                && generic.has_sufficient_entropy(m.as_str())
        })
    };

    // Rust/Python/Go variable bindings are not credentials.
    for code in [
        "        let payment_method_token = card_token.clone();",
        "let secret = client_secret;",
        "token = payment_method_token",
    ] {
        assert!(
            !is_reported(code),
            "should not flag identifier assignment: {code}"
        );
    }

    // Quoted literals, and unquoted values carrying digits or capitals, must
    // still be reported.
    for secret in [
        "api_key = \"sk_live_51abcdefghij\"",
        "API_KEY=abc123def456789",
        "password = \"hunter2hunter2\"",
        "token = api_key_2024",
    ] {
        assert!(is_reported(secret), "should flag credential: {secret}");
    }
}
