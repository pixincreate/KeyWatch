use key_watch::detector::Detector;

#[test]
fn test_allowlist_suppresses_matched_content() -> Result<(), String> {
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
fn test_detector_without_allowlist_allows_all() -> Result<(), String> {
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
fn test_keywords_prefilter_skips_non_matching_content() -> Result<(), String> {
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
    assert!(detector.has_keywords("APIKEY in uppercase"));
    Ok(())
}

#[test]
fn test_empty_keywords_allows_all_content() -> Result<(), String> {
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
fn test_entropy_filters_low_entropy_matches() -> Result<(), String> {
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
fn test_no_entropy_threshold_allows_all() -> Result<(), String> {
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
