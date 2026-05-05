# KeyWatch

A fast secret scanner for files and directories.

## Install

### Recommended: cargo install

```sh
cargo install key-watch
key-watch --version

# Enable aliases for your current shell session
eval "$(key-watch --init bash)"
```

To make aliases persistent, add the init line to your shell config file:

```sh
# bash
echo 'eval "$(key-watch --init bash)"' >> ~/.bashrc

# zsh
echo 'eval "$(key-watch --init zsh)"' >> ~/.zshrc
```

### Manual install from GitHub Releases

1. Download the correct binary for your OS/architecture from GitHub Releases.
2. Move it to a directory on your `PATH`, for example `~/.local/bin`.
3. Make it executable.
4. Verify it runs.
5. Enable aliases with `--init`.

```sh
mkdir -p ~/.local/bin
mv ~/Downloads/key-watch ~/.local/bin/key-watch
chmod +x ~/.local/bin/key-watch
~/.local/bin/key-watch --version

# Enable aliases for current shell session
eval "$(~/.local/bin/key-watch --init bash)"
```

Requires Rust 1.85+ (edition 2024) when building from source.

The canonical command is `key-watch`.
`keywatch` and `kw` are optional shell aliases exposed via `key-watch --init ...`.

## Uninstall

### If installed with `cargo install`

```sh
cargo uninstall key-watch
```

If you added aliases to your shell config, remove the init line you added earlier, for example:

```sh
# bash
sed -i.bak '/key-watch --init bash/d' ~/.bashrc

# zsh
sed -i.bak '/key-watch --init zsh/d' ~/.zshrc
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
key-watch --file secrets.txt

# Scan a directory
key-watch --dir .

# Verbose output (JSON)
key-watch --file secrets.txt --verbose

# Install git hook
key-watch --install-hook pre-commit
key-watch --install-hook pre-push

# Remove git hook
key-watch --uninstall-hook pre-commit
key-watch --uninstall-hook pre-push

# Install git hook globally via core.hooksPath
key-watch --install-hook pre-commit --global
key-watch --install-hook pre-push --global

# Remove global hook
key-watch --uninstall-hook pre-commit --global
key-watch --uninstall-hook pre-push --global

# Print shell aliases
eval "$(key-watch --init bash)"
```

## Options

- `--file <path>` - Scan one or more files (repeat the flag)
- `--dir <path>` - Scan a directory recursively
- `--output <path>` - Save report to file
- `--verbose` - Print full JSON output
- `--exclude <patterns>` - Comma-separated glob patterns to exclude
- `--exit-mode <mode>` - Exit behavior: `always` (always pass), `critical` (fail on HIGH only), `strict` (fail on any finding, default)
- `--install-hook <type>` - Install pre-commit or pre-push hook
- `--uninstall-hook <type>` - Remove pre-commit or pre-push hook
- `--global` - Use the global `core.hooksPath` directory for hook install/uninstall
- `--init <shell>` - Print shell aliases for `keywatch` and `kw`
- `--verify-integrity` - Check binary hasn't been tampered with
- `--allowed-repos <urls>` - Whitelist repos (pre-push)
- `--blocked-repos <urls>` - Block repos (pre-push)

## Aliases

- `key-watch` is the only shipped binary.
- `keywatch` and `kw` are optional aliases.
- `key-watch --init bash|zsh|fish|posix` prints shell aliases you can eval in your shell.
- `watch` is intentionally not used, to avoid colliding with the standard Unix `watch` command.

## Exit Codes

| Code | Meaning                                    |
| ---- | ------------------------------------------ |
| 0    | No secrets found (or `--exit-mode always`) |
| 1    | Secret found (in strict/critical mode)     |
| 2    | Runtime/configuration error                |

## Default Behavior

- **Repos**: All allowed (no restrictions)
- **Exit mode**: strict (fail on any finding)

## Git Hooks

- `--install-hook pre-commit|pre-push` installs a repo-local hook into `.git/hooks/`
- `--uninstall-hook pre-commit|pre-push` removes a KeyWatch hook from the same target
- `--install-hook ... --global` installs into Git's global hooks directory
- `--uninstall-hook ... --global` removes the hook from Git's global hooks directory
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
