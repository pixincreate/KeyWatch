# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Binary aliases: `keywatch`, `watch` (in addition to `key-watch`)
- Exit code modes: `--exit-mode always|critical|strict`
- Binary integrity verification: `--verify-integrity`
- Repository controls: `--allowed-repos`, `--blocked-repos`

### Security

- Shell injection protection in generated hooks
- Non-UTF8 file handling (graceful skip)

### Changed

- Simplified README (~60 lines)
- User-friendly output by default (summary, not JSON)
- Default exit mode: strict

### Fixed

- Portable detector loading (exe-relative path)
- Filenames with spaces handling

### Removed

- Legacy `hooks/keywatch.sh`
- `.pre-commit-config.yaml`

## [1.0.0] - 2025-02-16

- Initial release
- File/directory scanning
- Verbose JSON output
- Pre-commit/pre-push hooks