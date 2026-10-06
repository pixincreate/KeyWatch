# KeyWatch hardening plan

## Goal and constraints

Close the verified detection and scan-coverage gaps before making production-readiness claims.
Keep the CLI and module architecture.
Preserve the existing false-positive changes, except for exemptions that hide credentials.
Do not add project-specific fixture exemptions or dependencies.
Do not commit, publish, or replace the installed binary without permission.

## Stage 1: Complete credential matches

Status: Implemented and tested.
Repository CI remains blocked by baseline drift.

1. Add failing scanner tests for complete typed password values and token suffixes.
2. Fix `PasswordDetector` and `GenericKeyValueDetector` patterns and keyword coverage.
3. Support quoted JSON keys and multiple credential fields on one line.
4. Remove quoted snake-case and kebab-case exemptions.
5. Restrict placeholder exemptions to complete, selected documentation values.
6. Test baseline suppression through the executable in filesystem and staged modes.
7. Update conflicting test expectations and baseline compatibility documentation.
8. Run formatting, lint, debug tests, release tests, and the Rust 1.85 build check.
9. Inspect baseline drift without automatically accepting findings.

### Files

- `detectors.toml`
- `tests/scanner_tests.rs`
- `tests/baseline_tests.rs`
- `tests/detector_tests.rs`
- `README.md`
- `CHANGELOG.md`

### Approved acceptance tests

1. Typed Rust passwords and tokens containing `/` or `+` include the complete value.
2. Changing a password or token suffix produces a finding despite an existing baseline.
3. Moving an unchanged credential to another line remains suppressed by its baseline.
4. JSON credentials and bare `apikey`, `accesskey`, and `securitykey` names report.
5. Extended placeholders, passphrases, and quoted snake-case or kebab-case credentials report.
6. Exact selected placeholders and unquoted code references remain suppressed.

Keep detector names, severity levels, entropy thresholds, custom-rule behavior, and baseline format unchanged.
Corrected match text can change fingerprints.
Do not use legacy prefix fingerprints to suppress complete matches.
Review affected findings before updating a baseline.
This stage does not provide a complete Rust or JSON parser.

### Validation results

- `cargo test --locked --all-features --all-targets` exits with status 0.
  All 285 debug tests pass.
- `cargo test --locked --release --all-features --all-targets` exits with status 0.
  All 285 release tests pass.
- `cargo clippy --locked --all-features --all-targets -- -D warnings` exits with status 0.
- `cargo fmt --all --check` and `rustup run nightly cargo fmt --all --check` exit with status 0.
- `rustup run 1.85.0 cargo check --locked --offline --all-features --all-targets` exits with status 0.
- `git diff --check` exits with status 0.

Baseline inspection uses temporary copies and the repository's configured exclusions.
The scan reports 71 unbaselined findings with 62 distinct baseline identities.
These findings occur in test and workflow files.
The temporary merge also refreshes 49 existing locations.
The temporary prune removes 38 stale identities.
The repository baseline remains unchanged by this stage.
Review the findings before accepting any baseline changes.
The repository self-scan and baseline drift checks do not pass until this work is resolved.

## Stage 2: Git coverage and scan outcomes

Status: Implemented and tested through executable Git and report regressions.

Define predictable Git prefixes and hunk context.
Disclose shallow history without fetching automatically.
Address historical binary blobs and incomplete-scan exit behavior.
Separate detection results from coverage status.
Test exclusion paths, line attribution, shallow clones, and binary attributes through executable scans.

## Stage 3: Resource limits

Status: Implemented and tested.
Synthetic workload measurements are recorded in `docs/security-and-validation.md`.
Production-environment measurements remain a deployment requirement.
A whole-workspace measurement reaches the finding budget and exits with status 2 before producing a report.
Do not claim that this source tree can complete every large-repository scan.

Use checked size conversion and consistent byte limits across scan modes.
Bound long lines, chunks, decoded content, and retained findings.
Measure memory and execution time on representative repositories.
Do not claim large-project readiness without those measurements.

## Stage 4: Storage and configuration safety

Status: Implemented and tested.

Protect report and baseline writes against symlinks and partial writes.
Reject unknown override names.
Disclose skipped paths and define lockfile policy.
Document offline guessing risks for low-entropy baseline values.

## Stage 5: Accuracy and deployment evidence

Status: Implemented and tested within the documented scope.
The labeled corpus, benchmark script, report provenance, hook checks, and Action checks are included.
Published-binary authentication and untested platforms remain operational requirements.

Expand the labeled positive and negative corpus with paired examples.
Measure precision and recall without claiming universal detection.
Review suppression ownership, release provenance, and supported platforms.
Document unresolved coverage limits and the need for additional security controls.

You approved implementation of stages 2 through 5, with review after completion.
Changes to PII defaults, provider verification, release automation, or installation are not approved by this plan.

## Final review points

Review `docs/security-and-validation.md` for coverage, limits, trust boundaries, and measured accuracy.
The installed binary and existing installed hooks remain unchanged.
No commits, publication, dependency changes, or automatic baseline acceptance occur during this work.
The source changes preserve baseline format `1.0` but change some finding identities.
The JSON status can be `INCOMPLETE`, and explicit coverage failure overrides every severity exit mode.
Report and baseline writes require safe, operator-controlled directories.
Configuration rejects unknown overrides, duplicate detector names, and non-finite entropy thresholds.

### Final validation evidence

The following checks exit with status 0:

- `cargo test --locked --all-features --all-targets --quiet`: All 307 debug tests pass.
- `cargo test --locked --release --all-features --all-targets --quiet`: All 307 release tests pass.
- `cargo clippy --locked --all-features --all-targets -- -D warnings`.
- `rustup run nightly cargo fmt --all --check`.
- `rustup run 1.85.0 cargo check --locked --offline --all-features --all-targets`.
- `git diff --check`.
- `uv run --no-project --no-config python -B scripts/action_validation/validate.py`.
- `cargo audit --no-fetch --json`: The cached database reports zero vulnerabilities and no warnings.

The staged and history regressions include deleted binary paths with control characters.
Configuration tests reject non-finite thresholds before they can affect detection or report fingerprints.
The two documented false-positive corpus residuals remain unchanged.
The 34-case labeled corpus passes, but does not establish real-world precision or recall.

### Baseline review before draft PR preparation

The final baseline inspection uses temporary copies, trusted rules, and the repository's configured exclusions.
The self-scan exits with status 1, reports complete coverage, and finds 103 unbaselined occurrences.
These occurrences have 87 distinct baseline identities in tests, detector definitions, workflows, and the benchmark script.
The temporary merge changes the entry count from 225 to 312 and refreshes 63 existing locations.
The temporary prune removes 38 stale identities and leaves 274 entries.
The repository baseline remains unchanged by the hardening stages.
Review these findings before accepting them.
The repository self-scan and baseline drift checks remain blocked until that review is complete.

### Draft PR preparation

You approve review and baselining of confirmed synthetic fixtures before creating the draft PR.
The reviewed fixture update changes the baseline from 225 to 309 entries.
It includes test credentials, benchmark credentials, and the CI test token.
The required installed-scanner check of staged files exits with status 0.
The source-built repository self-scan still exits with status 1 and reports complete coverage.
Three findings remain: one workflow expression and two detector-definition matches.
Those findings are not accepted by the fixture baseline update.
CI self-scan and baseline drift checks remain blocked for your review.
The whole-workspace resource-budget limitation also remains unresolved.
