# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [2.0.1] - 2026-08-02

### Fixed

- GitHub Release asset publishing no longer fails when Action validation generates Python bytecode caches

## [2.0.0] - 2026-08-02

### Breaking Changes

- Public Rust APIs now return module-local typed errors instead of `String` or boxed errors. This affects CLI validation, baseline, configuration, detector initialization, scanner, hook, and `run_cli()` return types and requires a major-version release.

### Added

- **CRITICAL severity support** — findings can now be scored as Critical, High, Medium, or Low
- **Baseline suppression** — `scan --baseline <path>` suppresses known findings from previous scans; `--update-baseline` writes current findings to the baseline file
- **Inline suppression** — add `# keywatch:ignore` or `// keywatch:ignore` on a line to suppress findings
- **Per-detector allowlist** — each detector in `detectors.toml` can define `allowlist` regex patterns to suppress false positives
- **Keyword prefilter** — each detector can define `keywords` for fast prefiltering before regex runs
- **Entropy threshold filtering** — each detector can define `entropy` threshold to reject low-entropy false positives
- **Parallel scanning** — file scanning parallelized with rayon for multi-core speedup
- **Stdin scanning** — `scan --stdin` reads content from stdin instead of files
- **Git history scanning** — `scan --git-history` scans `git log -p` output for committed secrets
- Cloud/monitoring/AI service detectors: Vercel, Netlify, Supabase, Datadog, New Relic, Sentry, PagerDuty, Anthropic, HuggingFace, Groq, Replicate, LangSmith
- **GitHub Action** — composite action (`action.yml`) for CI/CD integration
- **Docker support** — multi-stage Dockerfile with `--locked` flag, stripped binary, non-root user, and git installed for `--git-history` scanning and hook installation
- **Public distribution verification** — the root GitHub Action verifies release binary and detector checksums, while GHCR images publish semver, major, and latest tags with provenance
- `.dockerignore` for optimized Docker builds
- **Config file support** — `.keywatch.toml` with custom rules, detector overrides, and exclude patterns
- **SARIF 2.1.0 output** — `--format sarif` enables GitHub Code Scanning and SARIF viewer integration
- **`--config` CLI flag** — specify a custom path to `.keywatch.toml`
- **Pre-commit `language: system`** — generated hooks use `language: system` for faster execution

### Changed

- `get_severity_counts()` now returns 4-tuple (Critical, High, Medium, Low) instead of 3-tuple
- `run_scan()` accepts optional `config` parameter for merging user configuration
- Simplified distribution to a single shipped binary: `key-watch`
- Git hook installation now supports first-class global hooks via `core.hooksPath`
- Installation guidance is now cargo-first, with manual GitHub Releases setup documented step by step
- CLI moved from flat top-level flags to subcommands: `scan`, `hook install|uninstall`, `init`, and `verify-integrity`
- Local hook installation now resolves Git's hooks directory directly, improving worktree and submodule compatibility
- `exit-mode critical` now fails on both HIGH and CRITICAL findings
- Detector descriptions and comments cleaned up for minimal noise
- Release preparation now synchronizes the Action version with Cargo metadata and runs CI before publishing tags
- CI now validates Action shell behavior, checksum failures, release automation, and container smoke behavior

### Fixed

- Cargo-installed and standalone binaries now fall back to embedded detector rules when no external `detectors.toml` is available
- CRITICAL severity was silently downgraded to LOW at runtime
- All clippy warnings resolved (`Default` impl, redundant closures, identity maps)
- Public API unit tests moved to `tests/` directory (only private API tests remain in `src/`)
- Baseline hash domain separator renamed from `SALT` to `DOMAIN_SEPARATOR` for clarity
- `Severity::from_string()` now trims whitespace from input before parsing
- `scan_stream()` chunk overlap fixed for accurate multiline detection on split chunks
- Graceful error handling when `git` is not installed on the system
- `action.yml` removed `eval "$CMD"` pattern for security
- `action.yml` removed hardcoded GitHub authentication header
- `.dockerignore` now preserves `Cargo.lock` for reproducible builds

### Removed

- Duplicate Cargo binary wrappers for `keywatch` and `watch`
- `scripts/install.sh` in favor of documented `cargo install` and manual release-binary setup
- ~1650 lines of redundant context-based detectors; kept only prefix-based detectors plus GenericKeyValueDetector

### Documentation

- README architecture documentation now uses three source-controlled D2 diagrams with generated SVGs for CLI modules and adapters, the scan pipeline, and detector/configuration trust boundaries

## [1.1.0] - 2026-05-05

### Added

- Binary aliases: `keywatch`, `watch` (in addition to `key-watch`)
- Exit code modes: `--exit-mode always|critical|strict`
- Binary integrity verification: `--verify-integrity`
- Repository controls: `--allowed-repos`, `--blocked-repos`
- Multiple file scanning: `--file file1.txt --file file2.txt`
- Indian ID detectors: Aadhaar, Voter ID (EPIC), PAN Card, ABHA Health ID

### Security

- Shell injection protection in generated hooks
- Non-UTF8 file handling (graceful skip)

### Changed

- Simplified README (~60 lines)
- User-friendly output by default (summary, not JSON)
- Default exit mode: strict
- Source builds now require Rust 1.85+ (edition 2024)

### Fixed

- Portable detector loading (exe-relative path)
- Filenames with spaces handling
- Hook repo allow/block rules are now enforced
- Exclude globs now work correctly for directory scans
- Runtime errors now use exit code `2` instead of `1`
- Hook subshell bug: exit now correctly blocks commits/pushes
- Hook detectors.toml check: removed hard CWD requirement (exe-relative works)
- Hook error messages now use correct binary name variable
- Duplicate file paths now deduplicated before scanning

### Removed

- Legacy `hooks/keywatch.sh`
- `.pre-commit-config.yaml`

## [1.0.0] - 2025-02-16

- Initial release
- File/directory scanning
- Verbose JSON output
- Pre-commit/pre-push hooks
