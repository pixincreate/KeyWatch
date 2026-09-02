//! Per-line and chunk scanning: the keyword prefilter, the detector accept
//! chain, and the stream/chunk drivers shared by every scan mode.

use crate::detector::Detector;
use crate::report::Finding;
use crate::scanner::ScannerError;
use aho_corasick::AhoCorasick;
use std::io::BufRead;

const INLINE_SUPPRESS: &str = "keywatch:ignore";

fn is_inline_suppressed(line: &str) -> bool {
    line.to_lowercase().contains(INLINE_SUPPRESS)
}

/// Lowercases `src` into `buf` without allocating a fresh string per line.
fn to_lowercase_into(src: &str, buf: &mut String) {
    buf.clear();
    buf.extend(src.chars().flat_map(char::to_lowercase));
}
/// Folds every distinct detector keyword into one Aho-Corasick automaton so a
/// line is checked against all keywords in a single pass instead of one
/// substring search per keyword per detector.
pub(super) struct KeywordPrefilter {
    automaton: Option<AhoCorasick>,
    /// Automaton pattern index -> indices of detectors owning that keyword.
    owners: Vec<Vec<usize>>,
    /// Detectors without keywords always run their regex.
    unconditional: Vec<usize>,
    detector_count: usize,
}

impl KeywordPrefilter {
    pub(super) fn new(line_detectors: &[&Detector]) -> Self {
        let mut patterns: Vec<&str> = Vec::new();
        let mut pattern_indices: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        let mut owners: Vec<Vec<usize>> = Vec::new();
        let mut unconditional = Vec::new();

        for (detector_index, detector) in line_detectors.iter().enumerate() {
            if detector.keywords.is_empty() {
                unconditional.push(detector_index);
                continue;
            }
            for keyword in &detector.keywords {
                let pattern_index = *pattern_indices.entry(keyword.as_str()).or_insert_with(|| {
                    patterns.push(keyword.as_str());
                    owners.push(Vec::new());
                    patterns.len() - 1
                });
                owners[pattern_index].push(detector_index);
            }
        }

        // If the automaton cannot be built, every keyword detector runs
        // unconditionally: slower, but it can never miss a secret.
        let automaton = match AhoCorasick::new(&patterns) {
            Ok(automaton) if !patterns.is_empty() => Some(automaton),
            _ => {
                unconditional = (0..line_detectors.len()).collect();
                None
            }
        };

        Self {
            automaton,
            owners,
            unconditional,
            detector_count: line_detectors.len(),
        }
    }

    /// Marks the detectors whose keywords occur in `lowered_line` in
    /// `candidates`, a scratch buffer reused across lines.
    fn candidates_into(&self, lowered_line: &str, candidates: &mut Vec<bool>) {
        candidates.clear();
        candidates.resize(self.detector_count, false);
        for &detector_index in &self.unconditional {
            candidates[detector_index] = true;
        }
        if let Some(automaton) = &self.automaton {
            for keyword_match in automaton.find_overlapping_iter(lowered_line) {
                for &detector_index in &self.owners[keyword_match.pattern().as_usize()] {
                    candidates[detector_index] = true;
                }
            }
        }
    }
}

pub(super) struct LineScanContext<'detectors> {
    line_detectors: &'detectors [&'detectors Detector],
    prefilter: KeywordPrefilter,
}

impl<'detectors> LineScanContext<'detectors> {
    pub(super) fn new(line_detectors: &'detectors [&'detectors Detector]) -> Self {
        Self {
            line_detectors,
            prefilter: KeywordPrefilter::new(line_detectors),
        }
    }
}

/// Per-line scratch buffers, reused across lines to avoid allocating in the
/// hot loop. Each scanning loop owns one (they are not shared across threads).
#[derive(Default)]
pub(super) struct LineScratch {
    lowered_line: String,
    candidates: Vec<bool>,
}
pub(super) fn scan_line_detectors(
    line: &str,
    line_number: usize,
    path: &str,
    context: &LineScanContext<'_>,
    scratch: &mut LineScratch,
    findings: &mut Vec<Finding>,
) {
    to_lowercase_into(line, &mut scratch.lowered_line);
    if scratch.lowered_line.contains(INLINE_SUPPRESS) {
        return;
    }

    context
        .prefilter
        .candidates_into(&scratch.lowered_line, &mut scratch.candidates);

    for (detector_index, detector) in context.line_detectors.iter().enumerate() {
        if !scratch.candidates[detector_index] {
            continue;
        }
        for mat in detector.regex.find_iter(line) {
            if detector.accepts_match(mat.as_str()) {
                findings.push(Finding {
                    file_path: path.to_string(),
                    line_number,
                    matched_content: mat.as_str().to_string(),
                    finding_type: detector.finding_type.clone(),
                    severity: detector.severity,
                    plugin_name: detector.name.clone(),
                });
            }
        }
    }
}

pub(super) fn scan_multiline_chunk(
    chunk: &str,
    line_offset: usize,
    path: &str,
    multiline_detectors: &[&Detector],
    findings: &mut Vec<Finding>,
) {
    if multiline_detectors.is_empty() {
        return;
    }
    let lowered_chunk = chunk.to_lowercase();
    for detector in multiline_detectors {
        if detector.has_keywords(&lowered_chunk) {
            for mat in detector.regex.find_iter(chunk) {
                let line_in_chunk = chunk[..mat.start()].matches('\n').count() + 1;
                let line_content = chunk
                    .lines()
                    .nth(line_in_chunk.saturating_sub(1))
                    .unwrap_or_default();
                let line_is_suppressed = is_inline_suppressed(line_content);

                if !line_is_suppressed && detector.accepts_match(mat.as_str()) {
                    findings.push(Finding {
                        file_path: path.to_string(),
                        line_number: line_offset + line_in_chunk,
                        matched_content: mat.as_str().to_string(),
                        finding_type: detector.finding_type.clone(),
                        severity: detector.severity,
                        plugin_name: detector.name.clone(),
                    });
                }
            }
        }
    }
}
pub(super) fn scan_content(
    content: &str,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext<'_>,
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut total_lines = 0;

    scan_multiline_chunk(content, 0, path, multiline_detectors, &mut findings);

    let mut scratch = LineScratch::default();
    for (line_idx, line) in content.lines().enumerate() {
        total_lines += 1;
        scan_line_detectors(
            line,
            line_idx + 1,
            path,
            context,
            &mut scratch,
            &mut findings,
        );
    }

    (findings, total_lines)
}
pub(super) fn scan_stream<ReaderType: BufRead>(
    reader: ReaderType,
    path: &str,
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, usize), ScannerError> {
    const CHUNK_SIZE: usize = 1000;
    const OVERLAP_LINES: usize = 50;

    let context = LineScanContext::new(line_detectors);
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut buffer: Vec<String> = Vec::with_capacity(CHUNK_SIZE + OVERLAP_LINES);
    let mut line_offset = 0;
    let mut scratch = LineScratch::default();

    for line_result in reader.lines() {
        let line = line_result.map_err(|source| ScannerError::ReadStream {
            path: path.to_string(),
            source,
        })?;
        total_lines += 1;

        scan_line_detectors(
            &line,
            total_lines,
            path,
            &context,
            &mut scratch,
            &mut findings,
        );

        buffer.push(line);

        if buffer.len() >= CHUNK_SIZE + OVERLAP_LINES {
            let chunk = buffer.join("\n");
            scan_multiline_chunk(
                &chunk,
                line_offset,
                path,
                multiline_detectors,
                &mut findings,
            );
            line_offset += buffer.len() - OVERLAP_LINES;
            buffer.drain(..buffer.len() - OVERLAP_LINES);
        }
    }

    if !buffer.is_empty() {
        let chunk = buffer.join("\n");
        scan_multiline_chunk(
            &chunk,
            line_offset,
            path,
            multiline_detectors,
            &mut findings,
        );
    }

    Ok((findings, total_lines))
}

#[cfg(test)]
mod tests {
    use crate::scanner::test_support::make_test_detector as make_detector;
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_scan_stream_detects_secrets() {
        let content = "AWS Key: AKIAABCDEFGHIJKLMNOP\npassword = 'mySecretPassword'\n";
        let reader = Cursor::new(content);
        let detectors = [
            make_detector("AWS", r"\bAKIA[A-Z0-9]{16}\b", "AWS Key", "HIGH"),
            make_detector(
                "Password",
                r#"password\s*=\s*['"][^'"]+['"]"#,
                "Password",
                "HIGH",
            ),
        ];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, total_lines) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();

        assert_eq!(total_lines, 2);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .any(|finding| finding.finding_type == "AWS Key")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.finding_type == "Password")
        );
    }

    #[test]
    fn test_scan_stream_respects_inline_suppression() {
        let content = "password = 'secret123' # keywatch:ignore\n";
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "Password",
            r#"password\s*=\s*['"][^'"]+['"]"#,
            "Password",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, _) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert!(
            findings.is_empty(),
            "Suppressed line should produce no findings"
        );
    }

    #[test]
    fn test_scan_stream_multiline_detector() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwKVPSmwaFkYLv\n-----END RSA PRIVATE KEY-----\n";
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "PrivateKey",
            r"(?s)-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*-----END (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            "Private Key",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, _) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "Private Key");
    }

    #[test]
    fn test_scan_stream_large_input_chunked() {
        let mut content = String::new();
        for line_number in 0..2500 {
            content.push_str(&format!(
                "line {}: password = 'secret{}'\n",
                line_number, line_number
            ));
        }
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "Password",
            r#"password\s*=\s*['"][^'"]+['"]"#,
            "Password",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.regex.as_str().contains("(?s)"));

        let (findings, total_lines) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert_eq!(total_lines, 2500);
        assert_eq!(
            findings.len(),
            2500,
            "Should find all 2500 secrets across chunks"
        );
    }

    #[test]
    fn test_prefilter_selects_detectors_with_overlapping_keywords() {
        // detectors.toml has genuinely overlapping keywords ("sk_" for Adyen,
        // "sk_test_" for Stripe). A non-overlapping search reports only the
        // shorter one and the longer detector silently never runs.
        let short = Detector::new(
            "Short",
            r"sk_\w+",
            "Short",
            "HIGH",
            &[],
            &["sk_".to_string()],
            None,
        )
        .unwrap();
        let long = Detector::new(
            "Long",
            r"sk_test_\w+",
            "Long",
            "HIGH",
            &[],
            &["sk_test_".to_string()],
            None,
        )
        .unwrap();
        let detectors = vec![&short, &long];
        let prefilter = KeywordPrefilter::new(&detectors);

        let mut candidates = Vec::new();
        prefilter.candidates_into("sk_test_51abcdef", &mut candidates);

        assert_eq!(
            candidates,
            vec![true, true],
            "both the shorter and longer keyword owners must be selected"
        );
    }
}
