# KeyWatch Missing Features Implementation Plan

**Issue:** https://github.com/pixincreate/KeyWatch/issues/68
**Branch:** `feat/missing-features`

## Problem
KeyWatch lacks features that make it usable on real codebases compared to gitleaks/detect-secrets. After audit, identified 10 gaps across 3 priority tiers.

## Vertical Slices (in dependency order)

### Slice 1: Fix CRITICAL Severity + Baseline Suppression (P0)
**Why first:** Makes KeyWatch usable on real repos. Without baseline, every scan dumps every finding.

**Files to modify:**
- `src/report.rs` — add CRITICAL to Severity enum
- `src/cli.rs` — add `--baseline` and `--update-baseline` flags
- `src/scanner.rs` — load baseline, suppress known findings
- `src/baseline.rs` — NEW: baseline model, serialization, comparison
- `src/lib.rs` — wire baseline into scan command
- `tests/` — integration tests for baseline behavior

**Test cases:**
1. CRITICAL in detectors.toml → Severity::Critical in report (not Low)
2. Baseline exists → known findings suppressed
3. Baseline missing → all findings reported
4. `--update-baseline` → writes baseline with current findings

### Slice 2: Inline Suppression (P0)
**Why second:** Reduces developer friction after baseline is in place.

**Files to modify:**
- `src/scanner.rs` — check for `# keywatch:ignore` on matched line
- `tests/` — test inline suppression

**Test cases:**
1. Line with `# keywatch:ignore` → finding suppressed
2. Line without comment → finding reported
3. Comment in the middle of line → still suppresses

### Slice 3: Allowlist per Detector (P1)
**Why third:** Fine-grained control for noisy detectors.

**Files to modify:**
- `src/detector.rs` — add allowlist fields to Detector struct
- `src/scanner.rs` — apply allowlist filtering
- `detectors.toml` — add example allowlists

**Test cases:**
1. Path matches allowlist → finding suppressed for that detector
2. Regex matches allowlist stopword → finding suppressed
3. No allowlist → normal behavior

### Slice 4: Keyword Prefilter (P1)
**Why fourth:** Performance boost after correctness features are solid.

**Files to modify:**
- `src/detector.rs` — add optional `keywords` field
- `src/scanner.rs` — build prefilter, skip lines without keywords
- `Cargo.toml` — may need `aho-corasick` or use HashSet

**Test cases:**
1. Line without keywords → no regex runs
2. Line with keyword → regex runs
3. Detector without keywords → always runs (backward compat)

### Slice 5: Entropy Threshold (P1)
**Why fifth:** Reduces false positives on generic patterns.

**Files to modify:**
- `src/detector.rs` — add optional `entropy` field
- `src/scanner.rs` — calculate Shannon entropy on match, filter if below threshold
- `tests/` — test entropy gating

**Test cases:**
1. High-entropy match → reported
2. Low-entropy match → suppressed
3. No entropy threshold → all matches reported

### Slice 6: Parallel Scanning with rayon (P2)
**Why sixth:** Speed improvement once correctness is solid.

**Files to modify:**
- `Cargo.toml` — add rayon dependency
- `src/scanner.rs` — parallelize file scanning

**Test cases:**
1. Parallel scan produces same results as sequential
2. Performance improvement on large repos

### Slice 7: Stdin Scanning (P2)
**Why seventh:** Flexibility for piping.

**Files to modify:**
- `src/cli.rs` — support `-` as path (stdin)
- `src/scanner.rs` — read from stdin when path is `-`

**Test cases:**
1. `echo "sk-abc..." | keywatch scan -` → detects secret
2. No stdin → error or skip

### Slice 8: Git History Scanning (P2)
**Why eighth:** Deep inspection after all basics are working.

**Files to modify:**
- `src/cli.rs` — add `--git-history` flag
- `src/scanner.rs` — execute `git log -p`, parse hunks

**Test cases:**
1. `keywatch scan . --git-history` → finds secrets in commits
2. Non-git repo → error

## Architecture Notes

- Baseline format: JSON with array of findings, each with file_path, line_number, matched_content hash
- Baseline comparison: hash of (file_path + line_number + matched_content) for stable matching
- Inline suppression: regex for `# keywatch:ignore` anywhere on line, case-insensitive
- Allowlist: per-detector paths (glob), regexes (regex), stopwords (string match)
- Keyword prefilter: build HashSet of all keywords from all detectors, check line.contains_any(keyword)
- Entropy: Shannon entropy H(X) = -sum(p_i * log2(p_i)) where p_i is char frequency in match

## Dependencies to Add

- `serde_json` (already in Cargo.toml? check)
- `rayon` (for parallel scan)
- `aho-corasick` (optional for keyword prefilter, or use HashSet)

## Rollback Plan

Each slice is independently revertable. If any slice causes issues, revert the commit and move to next slice. The baseline is the most critical — if it doesn't work, the tool is still usable (just noisy) which is the current state.

## Definition of Done

- All P0 features implemented and tested
- At least 2 P1 features implemented
- All existing tests pass
- README updated with new CLI flags
- Issue #68 updated with checklist
