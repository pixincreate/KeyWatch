# KeyWatch

KeyWatch scans files, directories, and git repositories for secrets such as API keys, tokens, passwords, and private keys.
It runs as a command-line tool, as a git hook, as a GitHub Action, and as a container image.

## Install

Install with cargo:

```sh
cargo install key-watch
key-watch --version
```

Or download a binary from GitHub Releases, place it on your `PATH`, and make it executable:

```sh
mkdir -p ~/.local/bin
mv ~/Downloads/key-watch ~/.local/bin/key-watch
chmod +x ~/.local/bin/key-watch
~/.local/bin/key-watch --version
```

Building from source requires Rust 1.85 or later.

The command is `key-watch`.
To use the shorter aliases `keywatch` and `kw`, add this line to your shell configuration file:

```sh
eval "$(key-watch init bash)"   # or: zsh, fish, posix
```

## Scan from the command line

Scan a file, a directory, or standard input:

```sh
key-watch scan secrets.txt          # one file
key-watch scan .                    # a directory tree
cat secrets.txt | key-watch scan --stdin
```

Scan a git repository:

```sh
key-watch scan --staged             # only the lines staged for commit
key-watch scan --git-history        # every commit on every branch
key-watch scan --git-history --rev-range abc123..def456   # a commit range
```

Control the output:

```sh
key-watch scan . --verbose               # print the full JSON report
key-watch scan . --output report.json    # write the report to a file
key-watch scan . --format sarif          # write SARIF instead of JSON
```

By default, KeyWatch prints one line per finding with the file, line number, and a redacted preview.
Reports never contain the full matched text unless you pass `--show-secrets`.

### Scan options

| Option | Purpose |
| ------ | ------- |
| `--exclude <patterns>` | Skip paths that match these comma-separated glob patterns |
| `--exit-mode <mode>` | `strict` fails on any finding (default), `critical` fails only on HIGH or CRITICAL findings, `always` never fails |
| `--fail-on-unscannable` | Fail when a file or directory could not be read |
| `--baseline <path>` | Use a specific baseline file |
| `--no-baseline-discovery` | Do not look for a baseline file automatically |
| `--update-baseline` | Record the current findings in the baseline instead of reporting them |
| `--prune-baseline` | With `--update-baseline`, also remove baseline entries that no longer match anything |
| `--config <path>` | Use a specific `.keywatch.toml` configuration file |
| `--no-config-discovery` | Ignore configuration and detector files found in the scanned repository |
| `--show-secrets` | Include the full matched text in reports |

Notes:

- Lock files such as `Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, and `yarn.lock` are always skipped.
  They contain checksums, not credentials.
- `--staged` reads the content you staged with `git add`, not the files on disk.
  A secret that is staged but already removed from the working copy is still found.
- `--git-history` scans every branch and tag.
  Use `--rev-range` to scan only a range of commits.
- A scan path that does not exist, is a symbolic link, or cannot be read is an error.
  The scan never reports a clean result for input it could not read.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | No secrets found, or `--exit-mode always` |
| 1 | Secrets found, or an unreadable file with `--fail-on-unscannable` |
| 2 | Invalid input, configuration error, or runtime error |

## Git hooks

KeyWatch installs two git hooks:

- The **pre-commit** hook scans the lines you staged.
  A secret in staged content blocks the commit.
  Findings in lines you did not change never block a commit.
- The **pre-push** hook scans the commits you are about to push.
  A secret in those commits blocks the push.
  Uncommitted files never block a push.

Install and remove hooks inside a repository:

```sh
key-watch hook install pre-commit
key-watch hook install pre-push
key-watch hook uninstall pre-commit
key-watch hook uninstall pre-push
```

Add `--global` to install or remove a hook for every repository on the machine:

```sh
key-watch hook install pre-commit --global
key-watch hook uninstall pre-commit --global
```

### Hook options

| Option | Applies to | Purpose |
| ------ | ---------- | ------- |
| `--exclude <patterns>` | pre-commit | Skip staged paths that match these patterns |
| `--allowed-repos <urls>` | pre-push | Allow pushes only to these repositories |
| `--blocked-repos <urls>` | pre-push | Block pushes to these repositories |

### How hooks behave

- Hooks always use the built-in detector rules.
  A repository cannot weaken its own scan by committing a modified detector file.
- Hooks respect a committed baseline file and `keywatch:ignore` markers.
- KeyWatch refuses to overwrite or remove a hook file it did not install.
- The first push of a branch scans the full history of that branch, because every commit on it is new to the remote.
  If that push reports old findings, record them in the baseline first.
- A global install sets `core.hooksPath` in your git configuration.
  Git then ignores each repository's own `.git/hooks` scripts.
  To keep a repository's own hooks instead, run `git config core.hooksPath .git/hooks` inside that repository.
  The KeyWatch hook then no longer runs there.

## Baselines

A baseline records findings you have reviewed and accepted, so later scans report only new findings.
The baseline file stores fingerprints of the findings, never the secrets themselves, and is safe to commit.

```sh
# Record the current findings
key-watch scan . --update-baseline

# Later scans report only new findings
key-watch scan .
```

KeyWatch finds a committed `.keywatch-baseline.json` automatically.
You do not need to pass `--baseline` on every scan.

## Ignore a single line

Add `keywatch:ignore` to a line to suppress findings on that line:

```sh
password = 'known-test-password' # keywatch:ignore
```

## Configuration

Place a `.keywatch.toml` file in the repository root to add rules, disable detectors, or exclude paths:

```toml
exclude = ["target/**"]

[[rules]]
name = "InternalToken"
pattern = "INT_[A-Za-z0-9]{32}"
finding_type = "Internal Token"
severity = "HIGH"

[overrides.EmailDetector]
enabled = false
```

Unknown keys in the configuration file are rejected, so a misspelled key cannot silently weaken a scan.

## GitHub Action

```yaml
name: Secret scan

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  keywatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: keywatch
        uses: pixincreate/KeyWatch@v2
        with:
          paths: "."
          exit-mode: strict
```

The Action installs a released KeyWatch binary, verifies its checksum, and writes a JSON report.
It supports Linux x64 and macOS runners.
Pin an exact release tag or commit SHA when you need a fixed version.

| Input | Default | Purpose |
| ----- | ------- | ------- |
| `version` | Action release version | Exact KeyWatch release to install |
| `paths` | `.` | Space-separated paths or globs to scan |
| `args` | empty | Extra scanner arguments; Action-managed options cannot be overridden |
| `exit-mode` | `strict` | `strict`, `critical`, or `always` |
| `output` | temporary file | Path for the JSON report |
| `config` | empty | Path to a trusted `.keywatch.toml` |
| `verbose` | `false` | Deprecated; enabling it is rejected to keep secrets out of logs |

The Action exposes `findings-count` and `exit-code` as step outputs.

## Container image

```sh
docker pull ghcr.io/pixincreate/keywatch:2
docker run --rm --volume "$PWD:/workspace:ro" ghcr.io/pixincreate/keywatch:2 scan .
```

Images are tagged `x.y.z`, `x.y`, `x`, and `latest`.
Use an exact version tag for reproducible results.
The image runs as a non-root user.

## Uninstall

If you installed with cargo:

```sh
cargo uninstall key-watch
```

If you installed a binary manually, delete it from your `PATH` directory:

```sh
rm -f ~/.local/bin/key-watch
```

In both cases, remove the `key-watch init` line from your shell configuration file if you added one.

## Development

```sh
cargo build --release
cargo test
cargo fmt
cargo clippy
```

Architecture diagrams live in `docs/architecture/`.
Edit the `.d2` sources and run `scripts/render-diagrams.sh render` to update the rendered images.

## License

KeyWatch is licensed under the GPL-3.0-only license.
See [LICENSE](LICENSE).
