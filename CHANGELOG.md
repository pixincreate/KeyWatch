# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `scan --staged` scans only the lines a commit adds
- Baselines are auto-discovered from `.keywatch-baseline.json`; `--no-baseline-discovery` opts out
- `update-baseline` workflow regenerates the baseline via a pull request

### Changed

- Pre-commit hooks scan the staged diff instead of whole files
- Config discovery searches parent directories up to the repository root
- Hook messages abbreviate the home directory as `~`

### Added

- CI scans this repository with KeyWatch and fails if the committed baseline has drifted
- `--prune-baseline` rewrites the baseline from current findings, dropping entries for deleted files and rotated credentials; requires `--update-baseline` and a whole-tree scan, and prints what it dropped

### Changed

- Reports redact matched text by default; `--show-secrets` opts into raw values, and matches shorter than 8 characters are always described by length only
- Reports summarise exclusions as a count plus a sample instead of listing every path, and report git-rendered binary files as `unscannable` rather than `excluded`

### Fixed

- `scan --git-history` applies `--exclude`, skips the baseline file, and reports real file paths instead of a synthetic `<git-history>` key that no baseline could match
- `scan --staged` is not fooled by `diff.relative`, which made git drop changes outside the current directory
- `--output` files are readable only by their owner, including when the file already existed with wider permissions
- Config is not trusted from a world-writable directory or file, so a `.keywatch.toml` dropped in `/tmp` cannot weaken scans beneath it
- `KEYWATCH_CONFIG_PATH` is ignored in trusted mode whenever it points inside the tree being scanned, wherever the process runs from
- Baseline suppression reports how many findings it hid, instead of applying silently
- `CreditCardDetector` requires an issuer prefix and a valid Luhn checksum, instead of matching any 13-16 digit run
- `HighEntropyDetector` could never fire (its 4.0 threshold is the ceiling for hex) and now runs, restricted to lines naming a credential
- PKCS#8 private key headers (`BEGIN PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`) are detected
- `PhoneNumberDetector` needs punctuation or a country code, so unix timestamps are not phone numbers
- Detectors can require a structural check via `validate = "luhn"`
- Hooks use built-in detectors, so a `detectors.toml` committed to a scanned repository can no longer replace the detector set and disable its own scan
- Files git renders as binary (including text marked `-diff` in `.gitattributes`) are read from the index instead of being reported clean
- `Base64Detector` matches from 28 characters, the length where entropy can actually separate base64 from identifiers
- `scan --staged` no longer misses findings under `color.ui = always` or custom diff prefixes
- Non-UTF-8 files no longer abort a staged scan
- The baseline file is no longer scanned as input to itself, including staged scans run from a subdirectory
- `GenericKeyValueDetector` and `RandomString` no longer flag code identifiers (`let payment_method_token = card_token`, snake_case serde attributes)
- `PasswordDetector` no longer flags `$PWD:`
- Piping output to a closed reader no longer panics, including `hook install` and `init`

### Performance

- Keyword matching uses a single Aho-Corasick pass per line: ~3x faster file scans, ~9x faster streams

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
