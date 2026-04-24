# KeyWatch

A fast secret scanner for files and directories.

## Install

```sh
# Recommended
cargo install --git https://github.com/pixincreate/KeyWatch.git

# Or use the install script
./scripts/install.sh

# Manual: download binary, add to PATH
```

## Usage

```sh
# Scan a file
keywatch --file secrets.txt

# Scan a directory
keywatch --dir .

# Verbose output (JSON)
keywatch --file secrets.txt --verbose

# Install git hook
keywatch --install-hook pre-commit
keywatch --install-hook pre-push
```

## Options

- `--file <path>` - Scan a single file
- `--dir <path>` - Scan a directory recursively
- `--output <path>` - Save report to file
- `--verbose` - Print full JSON output
- `--exclude <patterns>` - Comma-separated glob patterns to exclude
- `--exit-mode <mode>` - Exit behavior: `always` (always pass), `critical` (fail on HIGH only), `strict` (fail on any finding, default)
- `--install-hook <type>` - Install pre-commit or pre-push hook
- `--verify-integrity` - Check binary hasn't been tampered with
- `--allowed-repos <urls>` - Whitelist repos (pre-push)
- `--blocked-repos <urls>` - Block repos (pre-push)

## Aliases

`key-watch`, `keywatch`, `watch` are equivalent.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found (or `--exit-mode always`) |
| 1 | Secret found (in strict/critical mode) |

## Default Behavior

- **Repos**: All allowed (no restrictions)
- **Exit mode**: strict (fail on any finding)

## Development

```sh
cargo build --release
cargo test
cargo fmt
cargo clippy
```