# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Simplified distribution to a single shipped binary: `key-watch`
- Git hook installation now supports first-class global hooks via `core.hooksPath`
- Installation guidance is now cargo-first, with manual GitHub Releases setup documented step by step

### Added

- Hook uninstall support for local and global Git hooks
- `--init bash|zsh|fish|posix` to print shell aliases for `keywatch` and `kw`
- README now documents uninstall steps for both `cargo install` and manual GitHub Releases installs

### Removed

- Duplicate Cargo binary wrappers for `keywatch` and `watch`
- `scripts/install.sh` in favor of documented `cargo install` and manual release-binary setup

## [1.1.0] - 2026-05-05

### Added

- `keywatch` and `watch` aliases for `key-watch`
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
