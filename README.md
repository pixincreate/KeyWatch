# KeyWatch

A fast secret scanner for files and directories.

## Install

### Recommended: cargo install

```sh
cargo install key-watch
key-watch --version

# Enable aliases for your current shell session
eval "$(key-watch init bash)"
```

To make aliases persistent, add the init line to your shell config file:

```sh
# bash
echo 'eval "$(key-watch init bash)"' >> ~/.bashrc

# zsh
echo 'eval "$(key-watch init zsh)"' >> ~/.zshrc
```

### Manual install from GitHub Releases

1. Download the correct binary for your OS/architecture from GitHub Releases.
2. Move it to a directory on your `PATH`, for example `~/.local/bin`.
3. Make it executable.
4. Verify it runs.
5. Enable aliases with `init`.

```sh
mkdir -p ~/.local/bin
mv ~/Downloads/key-watch ~/.local/bin/key-watch
chmod +x ~/.local/bin/key-watch
~/.local/bin/key-watch --version

# Enable aliases for current shell session
eval "$(~/.local/bin/key-watch init bash)"
```

Requires Rust 1.85+ (edition 2024) when building from source.

The canonical command is `key-watch`.
`keywatch` and `kw` are optional shell aliases exposed via `key-watch init ...`.

## Uninstall

### If installed with `cargo install`

```sh
cargo uninstall key-watch
```

If you added aliases to your shell config, remove the init line you added earlier, for example:

```sh
# bash
sed -i.bak '/key-watch init bash/d' ~/.bashrc

# zsh
sed -i.bak '/key-watch init zsh/d' ~/.zshrc
```

### If installed manually from GitHub Releases

1. Remove the `key-watch` binary from your `PATH` directory.
2. Remove any shell init line you added for aliases.
3. Restart your shell or reload your shell config.

```sh
rm -f ~/.local/bin/key-watch

# If you added aliases for the current shell config, remove that line manually
# then reload your shell config, for example:
source ~/.bashrc
```

## Usage

```sh
# Scan a file
key-watch scan secrets.txt

# Scan a directory
key-watch scan .

# Verbose output (JSON)
key-watch scan secrets.txt --verbose

# Install git hook
key-watch hook install pre-commit
key-watch hook install pre-push

# Remove git hook
key-watch hook uninstall pre-commit
key-watch hook uninstall pre-push

# Install git hook globally via core.hooksPath
key-watch hook install pre-commit --global
key-watch hook install pre-push --global

# Remove global hook
key-watch hook uninstall pre-commit --global
key-watch hook uninstall pre-push --global

# Print shell aliases
eval "$(key-watch init bash)"

# Verify binary integrity
key-watch verify-integrity
```

## Options

- `scan <path>...` - Scan one or more files or directories
- `scan --output <path>` - Save report to file
- `scan --verbose` - Print full JSON output
- `scan --exclude <patterns>` - Comma-separated glob patterns to exclude
- `scan --exit-mode <mode>` - Exit behavior: `always` (always pass), `critical` (fail on HIGH only), `strict` (fail on any finding, default)
- `hook install <pre-commit|pre-push> [--global]` - Install a git hook
- `hook uninstall <pre-commit|pre-push> [--global]` - Remove a git hook
- `hook install pre-push --allowed-repos <urls>` - Whitelist repos for pre-push hooks
- `hook install pre-push --blocked-repos <urls>` - Block repos for pre-push hooks
- `hook install pre-commit --exclude <patterns>` - Exclude patterns for pre-commit scans
- `init <shell>` - Print shell aliases for `keywatch` and `kw`
- `verify-integrity` - Check binary hasn't been tampered with

## Aliases

- `key-watch` is the only shipped binary.
- `keywatch` and `kw` are optional aliases.
- `key-watch init bash|zsh|fish|posix` prints shell aliases you can eval in your shell.
- `watch` is intentionally not used, to avoid colliding with the standard Unix `watch` command.

## Exit Codes

| Code | Meaning                                         |
| ---- | ----------------------------------------------- |
| 0    | No secrets found (or `scan --exit-mode always`) |
| 1    | Secret found (in strict/critical mode)          |
| 2    | Runtime/configuration error                     |

## Default Behavior

- **Repos**: All allowed (no restrictions)
- **Exit mode**: strict (fail on any finding)

## Git Hooks

- `hook install pre-commit|pre-push` installs a repo-local hook into `.git/hooks/`
- `hook uninstall pre-commit|pre-push` removes a KeyWatch hook from the same target
- `hook install ... --global` installs into Git's global hooks directory
- `hook uninstall ... --global` removes the hook from Git's global hooks directory
- If `core.hooksPath` is already configured, KeyWatch installs into that directory
- Otherwise KeyWatch creates a managed hooks directory and configures `git config --global core.hooksPath`
- KeyWatch refuses to overwrite a non-KeyWatch global hook file
- KeyWatch also refuses to remove a non-KeyWatch global hook file

## Development

```sh
cargo build --release
cargo test
cargo fmt
cargo clippy
```
