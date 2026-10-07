use super::ScannerError;
use crate::report::Finding;
use std::io::Read;

pub(super) const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_LINE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_PATHS: usize = 100_000;
const MAX_FINDINGS: usize = 10_000;
const MAX_FINDING_BYTES: usize = 32 * 1024 * 1024;

pub(super) fn input_limit(megabytes: Option<u64>) -> Result<u64, ScannerError> {
    let requested = megabytes
        .unwrap_or(16)
        .checked_mul(1024 * 1024)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| ScannerError::ResourceLimit {
            reason: "Invalid maximum file size".to_string(),
        })?;
    Ok(requested.min(MAX_INPUT_BYTES))
}

pub(super) fn read_bounded(
    reader: impl Read,
    path: &str,
    limit: u64,
) -> Result<Vec<u8>, ScannerError> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ScannerError::ReadStream {
            path: path.to_string(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(ScannerError::ResourceLimit {
            reason: format!("Input exceeds {limit} bytes: {path}"),
        });
    }
    Ok(bytes)
}

#[derive(Default)]
pub(super) struct FindingBudget {
    count: usize,
    bytes: usize,
}

impl FindingBudget {
    pub(super) fn reserve(&mut self, bytes: usize) -> Result<(), ScannerError> {
        if self.count >= MAX_FINDINGS || bytes > MAX_FINDING_BYTES.saturating_sub(self.bytes) {
            return Err(ScannerError::ResourceLimit {
                reason: "Finding count or retained text exceeds the scan budget".to_string(),
            });
        }
        self.count += 1;
        self.bytes += bytes;
        Ok(())
    }
}

pub(super) fn check_findings(findings: &[Finding]) -> Result<(), ScannerError> {
    let mut budget = FindingBudget::default();
    for finding in findings {
        budget.reserve(
            finding.file_path.len()
                + finding.matched_content.len()
                + finding.finding_type.len()
                + finding.detector_name.len(),
        )?;
    }
    Ok(())
}
