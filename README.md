# KeyWatch

KeyWatch scans files and Git repositories for API keys, passwords, tokens, and private keys.
You can run it from the command line, Git hooks, GitHub Actions, or a container.

## Install

```sh
cargo install key-watch
```

You can also download a binary from [GitHub Releases](https://github.com/pixincreate/KeyWatch/releases) and put it on your `PATH`.
To build from source, use Rust 1.85 or later.

## Scan

```sh
key-watch scan .                                      # Scan a directory
key-watch scan secrets.txt                            # Scan a file
key-watch scan --staged                               # Scan staged changes
key-watch scan --git-history                          # Scan local Git history
key-watch scan --git-history --rev-range main..HEAD    # Scan a commit range
cat secrets.txt | key-watch scan --stdin               # Scan standard input
```

KeyWatch prints each finding with its file and line number.
Console output always redacts matched text.
Reports redact matched text unless you pass `--show-secrets`.

Write a report with:

```sh
key-watch scan . --output report.json
key-watch scan . --format sarif --output report.sarif
```

### Exit codes

- `0`: The scan passes your finding policy.
- `1`: The scan finds a secret, or coverage is incomplete with `--fail-on-unscannable`.
- `2`: The command has an input, configuration, or runtime error.

The default policy fails on any finding.
Use `--exit-mode critical` to fail only on HIGH or CRITICAL findings.
For CI, add `--fail-on-unscannable` so skipped inputs also fail the scan.

### Limits

- Git scans inspect changes, not complete repository snapshots.
  History scans need complete local history.
- Lockfiles are skipped by default.
  Add `--scan-lockfiles` to include them.
- Each input is limited to 16 MiB, and each line to 1 MiB.
  Binary files and skipped symbolic links make coverage incomplete.
- Finding and path limits can stop large scans with an error.

## Handle false positives

Review findings before you accept them in a baseline:

```sh
key-watch scan . --update-baseline
```

Later scans use `.keywatch-baseline.json` automatically.
The baseline stores hashes, but weak values can still be guessed from them.

To ignore one line, add `keywatch:ignore`:

```sh
password = 'known-test-password' # keywatch:ignore
```

## Configure

Put a `.keywatch.toml` file in your repository root:

```toml
exclude = ["target/**"]

[overrides.EmailDetector]
enabled = false
```

You can also add custom rules.
Run `key-watch scan --help` for all scan options.
Use `--no-config-discovery` when you do not trust the repository's rules or configuration.
This flag does not disable baselines or inline ignore markers.

## Git hooks

```sh
key-watch hook install pre-commit
key-watch hook install pre-push
```

The pre-commit hook scans staged changes.
The pre-push hook scans pushed commits and blocks HIGH or CRITICAL findings and incomplete coverage.
Use `hook uninstall` to remove a hook.

## GitHub Action

```yaml
jobs:
  secrets:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: pixincreate/KeyWatch@v3
        with:
          paths: "."
```

The Action downloads a released binary, not the source in your checkout.
See [CHANGELOG.md](CHANGELOG.md) for release changes.

## Container

```sh
docker run --rm -v "$PWD:/workspace:ro" ghcr.io/pixincreate/keywatch:3 scan .
```

## Development

```sh
cargo test --all-features --all-targets
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

## License

[GPL-3.0-only](LICENSE).
