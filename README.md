# KeyWatch

A fast secret scanner for files and directories.

## Install

```sh
# Recommended
cargo install --git https://github.com/pixincreate/KeyWatch.git

# Or use the install script (tries cargo first, then local binary)
./scripts/install.sh

# Or manually: download binary, add to ~/.local/bin
```

## Usage

```sh
# Scan a file
key-watch --file secrets.txt

# Scan a directory
key-watch --dir .

# Verbose output (JSON)
key-watch --file secrets.txt --verbose

# Install git hook
key-watch --install-hook pre-commit
key-watch --install-hook pre-push
```

## Options

- `--file <path>` - Scan a single file
- `--dir <path>` - Scan a directory recursively
- `--output <path>` - Save report to file
- `--verbose` - Print full JSON output
- `--exclude <patterns>` - Comma-separated glob patterns to exclude
- `--exit-mode <mode>` - Exit behavior: `always` (always pass), `critical` (fail on HIGH only), `strict` (fail on any finding, default)
- `--install-hook <type>` - Install pre-commit or pre-push hook

## Aliases

The following commands are equivalent: `key-watch`, `keywatch`, `watch`

## Default Behavior

- **Repos**: No restrictions by default (all repos allowed). Use `--allowed-repos` or `--blocked-repos` to control.
- **Exit code**: `strict` - exits non-zero if any secret is found. Use `--exit-mode` to change.

## Development

```sh
cargo build --release
cargo test
cargo fmt
cargo clippy
```