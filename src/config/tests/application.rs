use super::make_detectors;
use crate::config::{DetectorOverride, KeywatchConfig};
use crate::report::Severity;

#[test]
fn test_severity_deserialize_case_insensitive() {
    #[derive(serde::Deserialize)]
    struct Wrap {
        s: Severity,
    }

    for (input, expected) in [
        ("critical", Severity::Critical),
        ("CRITICAL", Severity::Critical),
        ("high", Severity::High),
        ("HIGH", Severity::High),
        ("medium", Severity::Medium),
        ("MEDIUM", Severity::Medium),
        ("low", Severity::Low),
        ("LOW", Severity::Low),
    ] {
        let toml_str = format!("s = \"{input}\"");
        let wrap: Wrap = toml::from_str(&toml_str)
            .unwrap_or_else(|err| panic!("failed to parse '{input}': {err}"));
        assert_eq!(wrap.s, expected, "input = {input}");
    }
}

#[test]
fn test_severity_deserialize_invalid_aborts() {
    #[derive(Debug, serde::Deserialize)]
    struct Wrap {
        #[allow(dead_code)]
        s: Severity,
    }

    let result: Result<Wrap, _> = toml::from_str("s = \"BOGUS\"");
    assert!(
        result.is_err(),
        "invalid severity must fail deserialization"
    );

    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("BOGUS"),
        "error should mention the bad value: {msg}"
    );
}

#[test]
fn test_custom_rule_default_severity_is_medium() {
    let toml_str = r#"
[[rules]]
name = "NoSev"
pattern = "\\bFOO\\b"
finding_type = "Test"
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).unwrap();
    let rule = &config.rules.unwrap()[0];
    assert_eq!(rule.severity, Severity::Medium);
}

#[test]
fn test_invalid_regex_returns_error() {
    let toml_str = r#"
[[rules]]
name = "Bad"
pattern = "[invalid"
finding_type = "Test"
severity = "HIGH"
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).unwrap();
    let mut detectors = make_detectors();
    let original_len = detectors.len();
    let result = config.apply_to(&mut detectors);

    assert!(result.is_err(), "invalid regex must return Err");
    let msg = result.unwrap_err();
    assert!(msg.contains("Bad"), "error must name the rule: {msg}");
    assert_eq!(
        detectors.len(),
        original_len,
        "detector vector must not be mutated on error"
    );
}

#[test]
fn test_no_partial_mutation_second_rule_invalid() {
    let toml_str = r#"
[[rules]]
name = "GoodRule"
pattern = "\\bGOOD\\b"
finding_type = "Good"
severity = "LOW"

[[rules]]
name = "BadRule"
pattern = "[invalid"
finding_type = "Bad"
severity = "HIGH"
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).unwrap();
    let mut detectors = make_detectors();
    let original_len = detectors.len();
    let result = config.apply_to(&mut detectors);

    assert!(result.is_err());
    assert_eq!(
        detectors.len(),
        original_len,
        "good rule must not be added when a later rule is invalid"
    );
}

#[test]
fn test_invalid_custom_severity_aborts_at_parse() {
    let toml_str = r#"
[[rules]]
name = "BadSev"
pattern = "\\bFOO\\b"
finding_type = "Test"
severity = "INVALID_SEVERITY"
"#;

    let result: Result<KeywatchConfig, _> = toml::from_str(toml_str);
    assert!(
        result.is_err(),
        "invalid custom severity must fail TOML parsing"
    );
}

#[test]
fn test_invalid_override_severity_aborts_at_parse() {
    let toml_str = r#"
[overrides]
SomeDet = { severity = "NOT_A_SEVERITY" }
"#;

    let result: Result<KeywatchConfig, _> = toml::from_str(toml_str);
    assert!(
        result.is_err(),
        "invalid override severity must fail TOML parsing"
    );
}

#[test]
fn test_override_severity_applies_typed() {
    let toml_str = r#"
[overrides]
ExistingDet = { severity = "LOW" }
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).unwrap();
    let mut detectors = make_detectors();
    config.apply_to(&mut detectors).unwrap();
    assert_eq!(detectors[0].severity, Severity::Low);
}

#[test]
fn test_override_disable() {
    let toml_str = r#"
[overrides]
ExistingDet = { enabled = false }
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).unwrap();
    let mut detectors = make_detectors();
    config.apply_to(&mut detectors).unwrap();
    assert!(detectors.is_empty(), "disabled detector must be removed");
}

#[test]
fn test_parse_minimal_config() {
    let toml_str = r#"
[[rules]]
name = "TestDetector"
pattern = "\\bTEST_SECRET_[A-Z]+\\b"
finding_type = "Test Secret"
severity = "HIGH"
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).expect("should parse");
    assert!(config.rules.is_some());
    assert_eq!(config.rules.as_ref().unwrap().len(), 1);
    assert_eq!(config.rules.as_ref().unwrap()[0].name, "TestDetector");
    assert!(config.overrides.is_none());
}

#[test]
fn test_parse_config_with_overrides() {
    let toml_str = r#"
[overrides]
AWSKeyDetector = { enabled = false }
GitHubTokenDetector = { severity = "CRITICAL" }
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).expect("should parse");
    let overrides = config.overrides.expect("overrides present");
    assert_eq!(overrides.len(), 2);

    let aws = overrides.get("AWSKeyDetector").expect("found");
    assert_eq!(aws.enabled, Some(false));
    assert!(aws.severity.is_none());

    let gh = overrides.get("GitHubTokenDetector").expect("found");
    assert_eq!(gh.severity, Some(Severity::Critical));
    assert!(gh.enabled.is_none());
}

#[test]
fn test_parse_override_severity_field_is_typed() {
    let toml_str = r#"
[overrides]
Det = { severity = "medium" }
"#;

    let config: KeywatchConfig = toml::from_str(toml_str).unwrap();
    let ov: &DetectorOverride = config.overrides.as_ref().unwrap().get("Det").unwrap();
    assert_eq!(ov.severity, Some(Severity::Medium));
}

#[test]
fn test_empty_config_is_default() {
    let config: KeywatchConfig = toml::from_str("").expect("empty should parse");
    assert!(config.rules.is_none());
    assert!(config.overrides.is_none());
    assert!(config.exclude.is_none());
}
