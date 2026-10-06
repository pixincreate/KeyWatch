# Security and validation

## Intended use

Use KeyWatch as an additional secret-detection control, not as proof that a repository contains no credentials.
Regex rules, entropy checks, and identifier exemptions can produce false positives and false negatives.
Provider verification is not implemented, and the scanner does not determine whether a credential is active.
The installed binary, published Action binary, container image, and hook templates can differ from this source tree.
Check their versions and release notes before you deploy them.

## Trust boundaries

Repository content, Git configuration, filenames, diffs, and object data are untrusted inputs.
Operator-selected configuration controls rules, exclusions, and severity.
Baseline entries and `keywatch:ignore` markers suppress findings.
Require review for these suppressions and for changes to scan policy.
Hooks ignore repository detector configuration but still trust repository baselines and inline ignore markers.
This does not create a tamper-proof gate against a malicious contributor.

For CI gates, use trusted detector rules, an operator-owned configuration, and reviewed suppressions.
Use `--fail-on-unscannable` to reject incomplete coverage.
Supply a trusted baseline explicitly when the repository baseline is not an approved policy source.
Protect configuration and baseline files through repository access controls and code review.
Do not expose privileged CI credentials to code from untrusted pull requests.

## Findings, coverage, and limits

Reports distinguish detected findings from scan coverage.
`INCOMPLETE` means some requested content or history could not be scanned.
It does not mean that the unavailable content contains a secret.
`COMPLETE` means the scanner completes its selected scope within its implemented capabilities.
It does not establish universal credential detection or include deliberately excluded files.
Review exclusions and coverage warnings with the findings.

The scanner enforces these limits:

| Resource | Limit |
| --- | --- |
| Raw logical input or Git addition hunk | 16 MiB |
| Line | 1 MiB |
| Path records | 100,000 |
| Findings per input and aggregate checks | 10,000 |
| Retained finding text and metadata per input and aggregate checks | 32 MiB |
| Concurrent filesystem batch | Four files |
| Retained Git standard error | 64 KiB |

`--max-file-size` lowers the raw input ceiling in filesystem, stdin, staged, and history modes.
Larger values do not raise the hard ceiling.
Limits produce incomplete coverage or a runtime error.
Partial input is not accepted as a clean scan or used to update a baseline.
Batch buffers, decoded content, detector definitions, paths, and reports also consume memory.
The retained-text limit is not a process memory limit.
Execution has no built-in wall-clock deadline; enforce a CI job timeout.

Multiline matching uses bounded complete inputs rather than fixed overlap windows.
Git text scans still inspect additions, not complete snapshots of every historical text file.
Credentials split across separate hunks or commits can therefore be missed.
Run a filesystem scan of the checked-out tree as well as the required Git scan.
Text rendered as binary uses actual Git blobs, including historical and deleted versions.
True binary content remains unscannable.
Shallow history remains incomplete until you fetch full history outside the scanner.
Archives, arbitrary obfuscation, recursive encoding, and complete language parsing are not supported.

## Secret storage and output

Reports redact matched content unless you explicitly use `--show-secrets`.
Do not upload unredacted reports to shared CI artifacts or logs.
The process still holds matched content in memory while scanning.
Restrict access to the scanner process and its environment.

Baseline hashes use domain-separated SHA-256 without a salt or keyed secret.
An attacker who obtains a baseline can test guesses for weak passwords offline.
Review this disclosure risk before publishing a baseline.
Rotate leaked credentials; adding a baseline entry does not remove a leak.

Report and baseline writes use private same-directory temporary files and atomic replacement.
They reject destination symlinks and unsafe immediate parent directories.
Control the parent directory and all ancestors.
This is not a defense against an attacker who can replace those ancestors.
The implementation does not promise directory-sync durability after power loss.

## Accuracy evidence

`tests/accuracy_corpus.toml` contains 34 synthetic cases: 20 credentials and 14 noncredentials.
The scanner reports the expected detector for every positive case and no findings for every negative case.
The measured case-level results are 20 true positives, 14 true negatives, zero false positives, and zero false negatives.
Precision and recall are both 1.000 on this corpus only.
These results do not measure real-world accuracy or prove that other provider formats are covered.
The separate false-positive corpus retains its two documented residual findings.
Expand the corpus when real reports reveal another failure class.
Add both the unwanted finding and a similar credential that must remain detectable.

## Synthetic workload measurements

Run the benchmark with an optimized binary:

```sh
cargo build --locked --release
uv run --no-project --no-config python -B scripts/benchmark.py target/release/key-watch
```

The script removes its generated files after execution.
The measured run uses macOS and the release build of this source tree.
The ordinary workload contains 2,000 files, 400,000 lines, and 9,600,000 bytes.

| Workload | Seconds | Peak resident bytes | Exit | Coverage |
| --- | ---: | ---: | ---: | --- |
| Many small files | 0.533 | 49,119,232 | 0 | Complete |
| Oversized line | 0.244 | 34,996,224 | 1 | Incomplete |
| Finding budget exceeded | 0.136 | 32,948,224 | 1 | Incomplete |
| 100,000 rejected multiline matches | 0.210 | 31,784,960 | 0 | Complete |

These are single-run measurements, not throughput guarantees or comparisons with other scanners.
No production CI environment, Windows runtime, or container runtime benchmark is measured here.
Measure your repository and CI environment before you rely on its scan duration or memory use.

### Existing repository measurement

A local Rust workspace scan excludes `target/**` and `**/node_modules/**` and disables configuration and baseline discovery.
It reaches the finding or retained-text budget after 20.328 seconds, with 126,812,160 peak resident bytes.
The command exits with status 2 and does not produce a report.
`--exit-mode always` does not suppress this runtime failure.
This measurement does not establish complete coverage of that workspace.
A source partition completes 340 files and 355,501 lines in 1.992 seconds, with 81,838,080 peak resident bytes.
Its report has complete coverage and 102 findings; the finding status is `FAIL`.
The command exits with status 0 because it uses `--exit-mode always`.
These findings are not labeled, so this measurement does not establish accuracy.
Baseline filtering occurs after scanning and does not bypass the raw-finding budget.
Use reviewed scan partitions and measure them before deployment.
Do not treat a budget failure as a clean result or increase limits without measuring the effect.

## Deployment and release evidence

JSON and SARIF reports contain a fingerprint of the effective detector definitions.
JSON also identifies the scanner version; SARIF identifies it in the tool driver.
The fingerprint covers patterns, keywords, allowlists, validators, entropy thresholds, and severity.
It is not a signature, binary attestation, or complete record of exclusions and baseline policy.
Record the scanned commit, command, configuration, baseline, and binary digest with your CI evidence.

Download checksums from the same release detect corruption, not compromise of the release publisher.
Pin Action references and container digests when you require reproducible inputs.
The Action supports Linux x64 and macOS, not Windows or Linux ARM64.
Reinstall hooks after changing the binary and hook templates.
Local tests do not validate an unpublished binary through the public release download path.
Release provenance, independently authenticated binaries, and platform deployment tests remain separate operational requirements.

Do not claim that this project is an independently audited or complete production security gate.
Use additional secret-management controls, credential rotation, and review processes.
