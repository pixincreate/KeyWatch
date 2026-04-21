# Changelog

## [Unreleased]

### Security

- **Shell injection protection** - Generated hooks escape user input (allowed_repos, blocked_repos, exclude patterns) with single-quote wrapping
- **Path validation** - Hooks verify `key-watch` is on PATH before executing

### Usability

- **Portable detector loading** - Checks executable directory first, falls back to CWD for detectors.toml
- **Non-UTF8 handling** - Binary files gracefully skipped (no crash on non-UTF8 content)
- **Filenames with spaces** - Pre-commit hook uses `IFS= read -r` for safe handling
- **Error distinction** - Exit code 1 = secret found, other codes = runtime error

### Cleanup

- Remove CLI help text typos ("push/push" → "push")
- Remove non-English text from help

### Testing

- Add behavioral tests for exit codes, verify_integrity, exclude patterns, portable config loading, hook validation
- 21 tests now pass

### Developer Experience

- Add `justfile` with common commands (`just run`, `just fmt`, `just clippy`, `just check`, etc.)

## [1.0.0] - 2025-02-16

- Initial Release
  - Support reading file, directory with verbose output in console
  - Output results to a file
  - Support various types of keys / secrets / tokens and etc.,