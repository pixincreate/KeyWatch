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
        generic
            .regex
            .find_iter(line)
            .any(|m| generic.accepts_match(m.as_str()))
    };

    // Rust/Python/Go variable bindings are not credentials.
    for code in [
        "        let payment_method_token = card_token.clone();",
        "let secret = client_secret;",
        "token = payment_method_token",
        // Rust type paths in field declarations are not credentials either:
        // `token: PaymentTokenData,` reads identically to `token: <10 random
        // chars>` to the pattern above, but a bare CamelCase value is a type.
        "token: PaymentTokenData,",
        "secret: ConfigValue,",
        "auth: NmiAuthType,",
    ] {
        assert!(
            !is_reported(code),
            "should not flag identifier assignment: {code}"
        );
    }

    // Quoted literals, and unquoted values carrying digits, must still be
    // reported. A value with digits or symbols cannot be a type path.
    for secret in [
        "api_key = \"sk_live_51abcdefghij\"",
        "API_KEY=abc123def456789",
        "password = \"hunter2hunter2\"",
        "token = api_key_2024",
        "token = Abc123def456",
    ] {
        assert!(is_reported(secret), "should flag credential: {secret}");
    }
}

/// Helper: does any built-in detector report this line?
fn reported_by(line: &str) -> Vec<String> {
    let detectors = key_watch::detector::initialize_detectors().expect("load detectors");
    let lowered = line.to_lowercase();
    detectors
        .iter()
        .filter(|d| d.has_keywords(&lowered))
        .filter(|d| d.regex.find_iter(line).any(|m| d.accepts_match(m.as_str())))
        .map(|d| d.name.clone())
        .collect()
}

#[test]
fn test_credit_card_requires_issuer_prefix_and_luhn() {
    for card in [
        "4111111111111111",    // Visa
        "5500 0000 0000 0004", // Mastercard, space separated
        "4111-1111-1111-1111", // dash separated
        "378282246310005",     // Amex
    ] {
        assert!(
            reported_by(card).contains(&"CreditCardDetector".to_string()),
            "should detect card: {card}"
        );
    }

    for card in ["6500000000000002", "6441111111111117"] {
        assert!(
            reported_by(card).contains(&"CreditCardDetector".to_string()),
            "should detect Discover card: {card}"
        );
    }

    for not_a_card in [
        "4111111111111112",              // Visa prefix, fails Luhn
        "1234567890123456",              // no issuer prefix
        "6411111111111111",              // 641x is neither Discover nor UnionPay
        "index aabbcc0..1111111 100644", // spans two unrelated numbers
        "timestamp = 1700000000123",
    ] {
        assert!(
            !reported_by(not_a_card).contains(&"CreditCardDetector".to_string()),
            "should not detect card in: {not_a_card}"
        );
    }
}

#[test]
fn test_phone_number_requires_separator_or_country_code() {
    for phone in ["call 415-123-4567", "(415) 123-4567", "+1 415 123 4567"] {
        assert!(
            reported_by(phone).contains(&"PhoneNumberDetector".to_string()),
            "should detect phone: {phone}"
        );
    }
    assert!(
        !reported_by("ts 1700000000").contains(&"PhoneNumberDetector".to_string()),
        "a bare 10-digit run is a timestamp, not a phone number"
    );
    assert!(
        !reported_by("call 555-123-4567").contains(&"PhoneNumberDetector".to_string()),
        "the fictional 555 exchange is allowlisted"
    );
}

#[test]
fn test_pkcs8_private_key_headers_are_detected() {
    // openssl genpkey and GCP/Azure service-account JSON emit these; before
    // the pattern required an algorithm word and matched neither.
    for header in [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    ] {
        assert!(
            !reported_by(header).is_empty(),
            "should detect private key header: {header}"
        );
    }
}

#[test]
fn test_high_entropy_hex_needs_credential_context() {
    let hex = "8b0e7153bf7c3706d85c524e440066559a6656c90bd5482a90a29b9fa5ff5180";
    assert!(
        reported_by(&format!("api_token = {hex}")).contains(&"HighEntropyDetector".to_string()),
        "hex assigned to a credential-named field should be reported"
    );
    assert!(
        !reported_by(&format!("let digest = compute({hex});"))
            .contains(&"HighEntropyDetector".to_string()),
        "a bare hex digest is indistinguishable from a hash and must not fire"
    );
}

#[test]
fn test_aws_example_key_is_allowlisted_but_real_keys_report() {
    // The AWS documentation example key/secret appear in READMEs everywhere.
    assert!(
        !reported_by("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
            .contains(&"AWSKeyDetector".to_string())
    );
    assert!(
        !reported_by("secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
            .iter()
            .any(|name| name == "Base64Detector" || name == "AWSKeyDetector")
    );
    assert!(
        reported_by("aws_access_key_id = AKIA1234567890ABCDEF")
            .contains(&"AWSKeyDetector".to_string()),
        "any other AKIA key must still be reported"
    );
}

#[test]
fn test_placeholder_values_are_allowlisted_in_both_detectors() {
    let placeholders = [
        "API_KEY=your-api-key-here",
        "DATABASE_PASSWORD=changeme",
        "SECRET_KEY=replace-me-please",
        "PASSWORD: changeme",
        "TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxx",
    ];
    for line in &placeholders {
        let names = reported_by(line);
        assert!(
            !names.contains(&"GenericKeyValueDetector".to_string())
                && !names.contains(&"PasswordDetector".to_string()),
            "{line} must not report, got {names:?}"
        );
    }

    // Mixed-case or digit-carrying values do not match the placeholder
    // shapes and stay reported.
    for line in [
        "password = 'mySecretPassword'",
        "token = YourSpecialToken123",
        "pwd: ReplaceThisRealSecret123",
        "api_key = \"sk_live_51abcdefghij\"",
    ] {
        let names = reported_by(line);
        assert!(
            names.contains(&"GenericKeyValueDetector".to_string())
                || names.contains(&"PasswordDetector".to_string()),
            "{line} must still be reported, got {names:?}"
        );
    }
}

#[test]
fn test_email_allowlists_documentation_domains_but_not_real_ones() {
    for email in [
        "contact: support@example.com",
        "alice@example.org",
        "reply-to: noreply@github.com",
        "author: 12345+user@users.noreply.github.com",
    ] {
        assert!(
            !reported_by(email).contains(&"EmailDetector".to_string()),
            "{email} must not report"
        );
    }
    assert!(
        reported_by("owner: bob.smith@company.io").contains(&"EmailDetector".to_string()),
        "a real-looking address is still reported"
    );
}

#[test]
fn test_fictional_555_numbers_are_allowlisted() {
    for phone in ["call 555-123-4567", "(212) 555-0123", "fax 555 123 4567"] {
        assert!(
            !reported_by(phone).contains(&"PhoneNumberDetector".to_string()),
            "{phone} must not report"
        );
    }
    assert!(
        reported_by("call 415-123-4567").contains(&"PhoneNumberDetector".to_string()),
        "a real-shaped number is still reported"
    );
}

#[test]
fn test_checksum_prefix_is_allowlisted_in_random_string() {
    let line = r#"integrity = "sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG""#;
    assert!(
        !reported_by(line).contains(&"RandomString".to_string()),
        "sha-prefixed checksums must not report"
    );
    assert!(
        reported_by(r#"token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd""#)
            .contains(&"RandomString".to_string()),
        "a quoted random string without a checksum prefix still reports"
    );
}
