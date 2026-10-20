//! Per-line and chunk scanning: the keyword prefilter, the detector accept
//! chain, and the stream/chunk drivers shared by every scan mode.

use super::limits::{FindingBudget, MAX_INPUT_BYTES, MAX_LINE_BYTES, read_bounded};
use crate::detector::Detector;
use crate::report::Finding;
use crate::scanner::ScannerError;
use aho_corasick::AhoCorasick;
use regex::Regex;
use std::io::BufRead;

const INLINE_SUPPRESS: &str = "keywatch:ignore";

/// Whether a line carries the inline suppression marker. `lowered_line` must
/// already be lowercased by [`to_lowercase_into`], so callers reuse the
/// buffer they already built instead of lowercasing twice.
fn is_inline_suppressed(lowered_line: &str) -> bool {
    lowered_line.contains(INLINE_SUPPRESS)
}

/// Reads a bounded patch line. Allows one prefix byte and a CRLF terminator.
/// The parser checks content length after removing the patch prefix.
pub(super) fn read_raw_line<ReaderType: BufRead>(
    reader: &mut ReaderType,
    path: &str,
    raw_line: &mut Vec<u8>,
) -> Result<bool, ScannerError> {
    raw_line.clear();
    let mut bytes_read = 0;
    loop {
        let available = reader
            .fill_buf()
            .map_err(|source| ScannerError::ReadStream {
                path: path.to_string(),
                source,
            })?;
        if available.is_empty() {
            break;
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if take > (MAX_LINE_BYTES + 3).saturating_sub(raw_line.len()) {
            return Err(ScannerError::ResourceLimit {
                reason: format!("Line exceeds {MAX_LINE_BYTES} bytes: {path}"),
            });
        }
        let finished = available[take - 1] == b'\n';
        raw_line.extend_from_slice(&available[..take]);
        reader.consume(take);
        bytes_read += take;
        if finished {
            break;
        }
    }
    if bytes_read == 0 {
        return Ok(false);
    }
    if raw_line.last() == Some(&b'\n') {
        raw_line.pop();
    }
    Ok(true)
}

pub(super) fn check_line_length(line: &str, path: &str) -> Result<(), ScannerError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ScannerError::ResourceLimit {
            reason: format!("Line exceeds {MAX_LINE_BYTES} bytes: {path}"),
        });
    }
    Ok(())
}

/// Lowercases `src` into `buf` without allocating a fresh string per line.
/// ASCII input (the overwhelming majority of scanned bytes) takes a
/// byte-per-byte fast path; the Unicode path is char-by-char and an order of
/// magnitude slower.
fn to_lowercase_into(src: &str, buf: &mut String) {
    buf.clear();
    if src.is_ascii() {
        buf.extend(src.bytes().map(|byte| byte.to_ascii_lowercase() as char));
    } else {
        buf.extend(src.chars().flat_map(char::to_lowercase));
    }
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

    /// Whether the combined keywordless gate may filter detectors: the gate
    /// is only sound while the automaton handles exactly the keyword
    /// detectors (on the fail-open path `unconditional` holds every detector,
    /// and gating them would risk missed secrets).
    fn gate_eligible(&self) -> bool {
        self.automaton.is_some()
    }

    /// Clears the keywordless detectors from `candidates` after the combined
    /// gate ruled the line out.
    fn clear_unconditional(&self, candidates: &mut [bool]) {
        for &detector_index in &self.unconditional {
            candidates[detector_index] = false;
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
    /// One combined any-of regex over the keywordless detectors: a single
    /// pass decides whether any of them can match the line, and their
    /// individual regex passes are skipped on lines that cannot. The gate is
    /// exact — is_match is existence, and each pattern is isolated in its own
    /// group so flags cannot leak between branches — so no match is ever
    /// lost; matching lines simply pay the gate plus their real passes.
    /// `None` when a gate cannot be built (fail open).
    unconditional_gate: Option<Regex>,
    /// Base64 runs long enough to hide an encoded credential. Candidates are
    /// decoded and their text is scanned once more, so `echo QVdTX0tFWT0...`
    /// does not smuggle a key past every format-anchored detector.
    base64_candidates: Regex,
}

impl<'detectors> LineScanContext<'detectors> {
    pub(super) fn new(line_detectors: &'detectors [&'detectors Detector]) -> Self {
        let prefilter = KeywordPrefilter::new(line_detectors);
        let unconditional_gate = prefilter
            .gate_eligible()
            .then(|| {
                let branches: Vec<&str> = line_detectors
                    .iter()
                    .filter(|detector| detector.keywords.is_empty())
                    .map(|detector| detector.regex.as_str())
                    .collect();
                let combined = format!(
                    "(?:{})",
                    branches
                        .iter()
                        .map(|branch| format!("(?:{branch})"))
                        .collect::<Vec<_>>()
                        .join("|")
                );
                Regex::new(&combined).ok()
            })
            .flatten();
        Self {
            line_detectors,
            prefilter,
            unconditional_gate,
            base64_candidates: Regex::new(r"[A-Za-z0-9+/]{24,}={0,2}")
                .expect("base64 candidate pattern is valid"),
        }
    }
}

/// Per-line scratch buffers, reused across lines to avoid allocating in the
/// hot loop. Each scanning loop owns one (they are not shared across threads).
#[derive(Default)]
pub(super) struct LineScratch {
    lowered_line: String,
    candidates: Vec<bool>,
    pub(super) budget: FindingBudget,
}
pub(super) fn scan_line_detectors(
    line: &str,
    line_number: usize,
    path: &str,
    context: &LineScanContext<'_>,
    scratch: &mut LineScratch,
    findings: &mut Vec<Finding>,
) -> Result<(), ScannerError> {
    to_lowercase_into(line, &mut scratch.lowered_line);
    if is_inline_suppressed(&scratch.lowered_line) {
        return Ok(());
    }

    run_line_detectors(line, line_number, path, context, scratch, findings)?;
    scan_decoded_base64(line, line_number, path, context, scratch, findings)
}

/// Decodes base64 runs on the line and scans the decoded text once (no
/// recursive decoding), attributing findings to the original line. Decoded
/// content must be printable text of a credential-plausible length;
/// anything else (hashes, compressed data, images) is rejected before any
/// detector runs.
fn scan_decoded_base64(
    line: &str,
    line_number: usize,
    path: &str,
    context: &LineScanContext<'_>,
    scratch: &mut LineScratch,
    findings: &mut Vec<Finding>,
) -> Result<(), ScannerError> {
    /// Shorter decoded payloads cannot hold a credential worth reporting.
    const MIN_DECODED_LENGTH: usize = 16;

    let candidates: Vec<String> = context
        .base64_candidates
        .find_iter(line)
        .map(|candidate| candidate.as_str().to_string())
        .collect();
    for candidate in candidates {
        let Some(decoded) = crate::utils::decode_base64_standard(&candidate) else {
            continue;
        };
        if decoded.len() < MIN_DECODED_LENGTH
            || !decoded
                .iter()
                .all(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            continue;
        }
        let Ok(text) = String::from_utf8(decoded) else {
            continue;
        };
        for decoded_line in text.lines() {
            run_line_detectors(decoded_line, line_number, path, context, scratch, findings)?;
        }
        let first_multiline = findings.len();
        scan_multiline_chunk(
            &text,
            line_number - 1,
            path,
            context.line_detectors,
            findings,
            &mut scratch.budget,
            false,
        )?;
        for finding in &mut findings[first_multiline..] {
            finding.line_number = line_number;
        }
    }
    Ok(())
}

/// The detector matching core, shared by the raw line and its decoded
/// base64 payloads. Inline suppression is handled by the caller on the raw
/// line only: a marker hidden inside encoded content must not suppress.
fn run_line_detectors(
    line: &str,
    line_number: usize,
    path: &str,
    context: &LineScanContext<'_>,
    scratch: &mut LineScratch,
    findings: &mut Vec<Finding>,
) -> Result<(), ScannerError> {
    to_lowercase_into(line, &mut scratch.lowered_line);
    context
        .prefilter
        .candidates_into(&scratch.lowered_line, &mut scratch.candidates);
    let run_unconditional = context
        .unconditional_gate
        .as_ref()
        .is_none_or(|gate| gate.is_match(line));
    if !run_unconditional {
        context
            .prefilter
            .clear_unconditional(&mut scratch.candidates);
    }

    for (detector_index, detector) in context.line_detectors.iter().enumerate() {
        if !scratch.candidates[detector_index] {
            continue;
        }
        for captures in detector.regex.captures_iter(line) {
            let Some(matched) = captures.get(0) else {
                continue;
            };
            if detector.accepts_captures(&captures) {
                scratch.budget.reserve(
                    path.len() + matched.len() + detector.finding_type.len() + detector.name.len(),
                )?;
                findings.push(Finding {
                    file_path: path.to_string(),
                    line_number,
                    matched_content: matched.as_str().to_string(),
                    finding_type: detector.finding_type.clone(),
                    severity: detector.severity,
                    detector_name: detector.name.clone(),
                });
            }
        }
    }
    Ok(())
}

pub(super) fn scan_multiline_chunk(
    chunk: &str,
    line_offset: usize,
    path: &str,
    multiline_detectors: &[&Detector],
    findings: &mut Vec<Finding>,
    budget: &mut FindingBudget,
    respect_suppression: bool,
) -> Result<(), ScannerError> {
    if multiline_detectors.is_empty() {
        return Ok(());
    }
    let lowered_chunk = chunk.to_lowercase();
    for detector in multiline_detectors {
        let mut previous_start = 0;
        let mut line_in_chunk = 1;
        let mut line_start = 0;
        if detector.has_keywords(&lowered_chunk) {
            for captures in detector.regex.captures_iter(chunk) {
                let Some(matched) = captures.get(0) else {
                    continue;
                };
                if !matched.as_str().contains('\n') {
                    continue;
                }
                let trimmed = matched.as_str().trim_end_matches(['\r', '\n']);
                if !trimmed.contains('\n')
                    && detector
                        .regex
                        .find(trimmed)
                        .is_some_and(|found| found.as_str() == trimmed)
                {
                    // A trailing line delimiter does not create another
                    // credential when the line-local pass covers the match.
                    continue;
                }
                if !detector.accepts_captures(&captures) {
                    continue;
                }
                // Matches occur in source order. Advance once through each
                // intervening prefix instead of recounting the whole input.
                for (offset, _) in chunk[previous_start..matched.start()].match_indices('\n') {
                    line_in_chunk += 1;
                    line_start = previous_start + offset + 1;
                }
                previous_start = matched.start();
                let line_content = chunk[line_start..].split('\n').next().unwrap_or_default();
                let line_is_suppressed =
                    respect_suppression && is_inline_suppressed(&line_content.to_lowercase());

                if !line_is_suppressed {
                    budget.reserve(
                        path.len()
                            + matched.len()
                            + detector.finding_type.len()
                            + detector.name.len(),
                    )?;
                    findings.push(Finding {
                        file_path: path.to_string(),
                        line_number: line_offset + line_in_chunk,
                        matched_content: matched.as_str().to_string(),
                        finding_type: detector.finding_type.clone(),
                        severity: detector.severity,
                        detector_name: detector.name.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}
pub(super) fn scan_content(
    content: &str,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext<'_>,
) -> Result<(Vec<Finding>, usize), ScannerError> {
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut scratch = LineScratch::default();

    scan_multiline_chunk(
        content,
        0,
        path,
        multiline_detectors,
        &mut findings,
        &mut scratch.budget,
        true,
    )?;

    for (line_idx, line) in content.lines().enumerate() {
        check_line_length(line, path)?;
        total_lines += 1;
        scan_line_detectors(
            line,
            line_idx + 1,
            path,
            context,
            &mut scratch,
            &mut findings,
        )?;
    }

    Ok((findings, total_lines))
}

/// How a streaming scan treats NUL bytes: stdin is scanned through, while
/// a filesystem file containing one is binary and stops the scan.
#[derive(Clone, Copy)]
enum BinaryHandling {
    ScanThrough,
    StopAtNul,
}

/// Outcome of a streaming scan.
pub(super) struct StreamScan {
    pub(super) findings: Vec<Finding>,
    pub(super) total_lines: usize,
    /// A NUL byte was seen: the input is binary. `findings` is empty.
    pub(super) binary: bool,
}

/// Reads a bounded logical input and checks complete cross-line matches.
fn scan_lines<R: BufRead>(
    reader: &mut R,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext,
    binary_handling: BinaryHandling,
    max_bytes: u64,
) -> Result<StreamScan, ScannerError> {
    let bytes = read_bounded(reader, path, max_bytes)?;
    let binary = matches!(binary_handling, BinaryHandling::StopAtNul) && bytes.contains(&0);
    let (findings, total_lines) = if binary {
        (Vec::new(), 0)
    } else {
        scan_content(
            &String::from_utf8_lossy(&bytes),
            path,
            multiline_detectors,
            context,
        )?
    };
    Ok(StreamScan {
        findings,
        total_lines,
        binary,
    })
}

pub(super) fn scan_stream<ReaderType: BufRead>(
    mut reader: ReaderType,
    path: &str,
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, usize), ScannerError> {
    let context = LineScanContext::new(line_detectors);
    let scanned = scan_lines(
        &mut reader,
        path,
        multiline_detectors,
        &context,
        BinaryHandling::ScanThrough,
        MAX_INPUT_BYTES,
    )?;
    Ok((scanned.findings, scanned.total_lines))
}

/// Streams a filesystem file with binary detection: the first NUL byte
/// marks the file binary, stops the scan, and discards partial findings -
/// matching the whole-read behaviour this replaces.
pub(super) fn scan_file_stream<ReaderType: BufRead>(
    reader: &mut ReaderType,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext,
    max_bytes: u64,
) -> Result<StreamScan, ScannerError> {
    scan_lines(
        reader,
        path,
        multiline_detectors,
        context,
        BinaryHandling::StopAtNul,
        max_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::test_support::make_test_detector as make_detector;
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
            .partition(|detector| detector.is_multiline());

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
            .partition(|detector| detector.is_multiline());

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
            .partition(|detector| detector.is_multiline());

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
            .partition(|detector| detector.is_multiline());

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
        // detectors.toml has genuinely overlapping keywords ("sk_live" for
        // Plaid, "sk_live_" for Stripe and Paystack). A non-overlapping
        // search reports only the shorter one and the longer detector
        // silently never runs.
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

    #[test]
    fn test_scan_stream_multiline_inside_overlap_reports_once() {
        // A multiline secret sitting entirely inside the 50-line carry
        // between two windows is scanned by both; it must be reported once.
        let mut content = String::new();
        for line in 0..1000 {
            content.push_str(&format!("filler {line}\n"));
        }
        content.push_str("BEGIN KEY\nmaterial\nEND KEY\n"); // lines 1001..1003
        for line in 0..1100 {
            content.push_str(&format!("tail {line}\n"));
        }

        let detector = make_detector("Block", r"(?s)BEGIN KEY.*?END KEY", "Block", "HIGH");
        let detectors = [detector];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) =
            detectors.iter().partition(|d| d.is_multiline());
        let (findings, total_lines) = scan_stream(
            Cursor::new(content),
            "<test>",
            &multiline_detectors,
            &line_detectors,
        )
        .unwrap();

        assert_eq!(total_lines, 2103);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.line_number)
                .collect::<Vec<_>>(),
            vec![1001],
            "overlap windows must not duplicate a multiline match"
        );
    }

    #[test]
    fn test_scan_stream_multiline_crossing_window_boundary_reports_once() {
        // The secret starts in window 1 but only completes inside window 2's
        // content: exactly one finding, attributed to the true start line.
        let mut content = String::new();
        for line in 0..1048 {
            content.push_str(&format!("filler {line}\n"));
        }
        content.push_str("BEGIN KEY\nmaterial\nEND KEY\n"); // lines 1049..1051
        for line in 0..1200 {
            content.push_str(&format!("tail {line}\n"));
        }

        let detector = make_detector("Block", r"(?s)BEGIN KEY.*?END KEY", "Block", "HIGH");
        let detectors = [detector];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) =
            detectors.iter().partition(|d| d.is_multiline());
        let (findings, _) = scan_stream(
            Cursor::new(content),
            "<test>",
            &multiline_detectors,
            &line_detectors,
        )
        .unwrap();

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.line_number)
                .collect::<Vec<_>>(),
            vec![1049]
        );
    }
}

/// Decodes UTF-16 content that starts with a byte-order mark, lossily so a
/// broken pair cannot abort a scan. Returns `None` when no BOM is present:
/// without one, distinguishing UTF-16 from binary is guesswork, and guessing
/// wrong would scan garbage. Windows tools that write UTF-16 (`Out-File`,
/// Notepad) write the BOM.
pub(super) fn decode_utf16_bom(bytes: &[u8]) -> Option<String> {
    let (first, second) = (bytes.first()?, bytes.get(1)?);
    let little_endian = match (first, second) {
        (0xFF, 0xFE) => true,
        (0xFE, 0xFF) => false,
        _ => return None,
    };
    let units = bytes[2..].chunks_exact(2).map(|pair| {
        if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        }
    });
    Some(
        char::decode_utf16(units)
            .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
    )
}

#[cfg(test)]
mod utf16_tests {
    use super::decode_utf16_bom;

    #[test]
    fn decodes_both_byte_orders_and_rejects_bomless_input() {
        let mut little = vec![0xFF, 0xFE];
        for unit in "AKIA test".encode_utf16() {
            little.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_utf16_bom(&little).as_deref(), Some("AKIA test"));

        let mut big = vec![0xFE, 0xFF];
        for unit in "AKIA test".encode_utf16() {
            big.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(decode_utf16_bom(&big).as_deref(), Some("AKIA test"));

        assert_eq!(decode_utf16_bom(b"plain ascii"), None);
        assert_eq!(decode_utf16_bom(b""), None);
        // A lone unpaired surrogate decodes to the replacement character
        // instead of failing.
        let broken = [0xFF, 0xFE, 0x00, 0xD8];
        assert!(decode_utf16_bom(&broken).is_some());
    }
}
