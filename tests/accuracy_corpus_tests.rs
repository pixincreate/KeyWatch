use key_watch::{cli::ScanArgs, scanner::run_scan};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    input: String,
    detector: Option<String>,
}

#[test]
fn labeled_credentials_and_noncredentials_match_expected_scan_results() {
    let corpus: Corpus = toml::from_str(include_str!("accuracy_corpus.toml")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.txt");
    let mut true_positive = 0;
    let mut true_negative = 0;
    let mut false_positive = 0;
    let mut false_negative = 0;
    let mut failures = Vec::new();
    for case in corpus.cases {
        fs::write(&path, &case.input).unwrap();
        let (findings, metadata) = run_scan(
            &ScanArgs {
                paths: vec![path.to_str().unwrap().to_string()],
                no_config_discovery: true,
                no_baseline_discovery: true,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        assert!(
            metadata.is_complete(),
            "{} has incomplete coverage",
            case.name
        );
        match case.detector {
            Some(detector)
                if findings
                    .iter()
                    .any(|finding| finding.detector_name == detector) =>
            {
                true_positive += 1
            }
            Some(detector) => {
                false_negative += 1;
                failures.push(format!("{} misses {detector}", case.name));
            }
            None if findings.is_empty() => true_negative += 1,
            None => {
                false_positive += 1;
                failures.push(format!("{} reports {} findings", case.name, findings.len()));
            }
        }
    }
    let precision = true_positive as f64 / (true_positive + false_positive) as f64;
    let recall = true_positive as f64 / (true_positive + false_negative) as f64;
    println!(
        "Synthetic case results: TP={true_positive}, TN={true_negative}, FP={false_positive}, FN={false_negative}, precision={precision:.3}, recall={recall:.3}"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
