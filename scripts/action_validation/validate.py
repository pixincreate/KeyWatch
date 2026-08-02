#!/usr/bin/env python3
"""Static regression checks for the KeyWatch composite action."""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

from keywatch_action_scenarios import run_install_scenarios, run_scan_scenarios
from release_script_scenario import run_release_scenario
ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"


def run_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if re.match(r"^\s{6}run:\s*\|\s*$", line):
            block: list[str] = []
            index += 1
            while index < len(lines):
                next_line = lines[index]
                if next_line and not next_line.startswith("        "):
                    break
                block.append(next_line[8:] if next_line.startswith("        ") else "")
                index += 1
            blocks.append("\n".join(block))
            continue
        index += 1
    return blocks


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate_workflows() -> None:
    workflows = ROOT / ".github" / "workflows"
    ci = (workflows / "ci.yml").read_text(encoding="utf-8")
    release = (workflows / "release.yml").read_text(encoding="utf-8")
    docker = (workflows / "docker-publish.yml").read_text(encoding="utf-8")
    validator = "python3 scripts/action_validation/validate.py"

    require(validator in ci, "CI must validate the public Action")
    require("docker build" in ci, "CI must build the public container")
    require("docker run" in ci, "CI must smoke-test the public container")
    require("  preflight:" in release, "release workflow must have a preflight job")
    require("needs: preflight" in release, "publishing must depend on preflight")
    require("cargo test --release" in release, "release preflight must test release mode")
    require("cargo clippy" in release, "release preflight must run Clippy")
    require(validator in release, "release preflight must validate distribution")
    require("attestations: write" in docker, "container publishing must allow attestations")
    require("id-token: write" in docker, "container publishing must allow OIDC provenance")
    require("IMAGE_NAME: pixincreate/keywatch" in docker, "container image and attestation names must match")
    require("type=semver,pattern={{major}}" in docker, "container publishing must create a major tag")
    require("type=raw,value=latest" in docker, "container publishing must create a latest tag")
    require("workflow_dispatch:" not in docker, "manual runs must not overwrite stable container tags")
    require("tag_version=${GITHUB_REF_NAME#v}" in docker, "container publishing must validate the release tag")
    require('test "$tag_version" = "$cargo_version"' in docker, "container tag must match Cargo.toml")
    require('test "$tag_version" = "$action_version"' in docker, "container tag must match the Action version")
    require('grep -Fq "## [$tag_version] -" CHANGELOG.md' in docker, "container tag must exist in the changelog")
    require("id: push" in docker, "container build digest must be addressable")
    require("actions/attest-build-provenance@" in docker, "container publishing must attest provenance")
    require("subject-digest: ${{ steps.push.outputs.digest }}" in docker, "attestation must bind the pushed digest")
    require("cargo build --locked --release" in release, "release binaries must use the checked-in lockfile")


def main() -> int:
    text = ACTION.read_text(encoding="utf-8")
    cargo_toml = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    blocks = run_blocks(text)
    shell = "\n".join(blocks)

    cargo_version = re.search(r'^version = "([^"]+)"$', cargo_toml, re.MULTILINE)
    action_version = re.search(
        r"(?m)^  version:\n    description:.*\n    required: false\n"
        r"    default: '([^']+)'$",
        text,
    )
    require(cargo_version is not None, "Cargo.toml package version is missing")
    require(action_version is not None, "Action version input/default is missing")
    require(
        action_version.group(1) == cargo_version.group(1),
        "Action default version must match Cargo.toml",
    )

    for block_index, block in enumerate(blocks, start=1):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".bash") as script:
            script.write(block)
            script.flush()
            result = subprocess.run(
                ["bash", "-n", script.name],
                check=False,
                text=True,
                capture_output=True,
            )
        require(
            result.returncode == 0,
            f"run block {block_index} is not valid Bash: {result.stderr.strip()}",
        )

    forbidden_fragments = [
        "sudo ",
        "eval ",
        "${VERBOSE:+--verbose}",
        "${INPUT_VERBOSE:+--verbose}",
        "key-watch scan $",
        "FINDINGS_COUNT=\"0\"",
        "|| echo \"0\"",
    ]
    for fragment in forbidden_fragments:
        require(fragment not in shell, f"forbidden shell fragment remains: {fragment}")

    require("${{ inputs." not in shell, "inputs must be routed through step env, not run blocks")
    require("keywatch_args=(scan --no-config-discovery)" in shell, "Action scans must disable untrusted config discovery")
    require("keywatch_args+=(--config \"$INPUT_CONFIG\")" in shell, "explicit trusted config input must be supported")
    require("read -r -a paths" in shell, "paths input must be parsed without shell evaluation")
    require("compgen -G \"$path_token\"" in shell, "path globs must expand without shell evaluation")
    require("expanded_paths+=(\"$path_token\")" in shell, "unmatched globs and metachar literals must stay literal")
    require("keywatch_args+=(-- \"${expanded_paths[@]}\")" in shell, "path operands must be guarded by --")
    require("read -r -a extra_args" in shell, "args input must be parsed without shell evaluation")
    require("managed by action inputs" in shell, "args must not override verbose/output/exit-mode inputs")
    require("--verbose|--verbose=*|-v*" in shell, "all verbose arg forms must be rejected")
    require("--format|--format=*|-f|-f*" in shell, "all format arg forms must be rejected")
    require("--config|--config=*|--no-config-discovery|--no-config-discovery=*" in shell, "config discovery controls must be managed by the Action")
    require("verbose output is disabled" in shell, "verbose mode must not log matched secrets")
    require("false|0|no|off|\"\")" in shell, "verbose=false must be an explicit non-verbose case")
    require("asset_arch=\"aarch64\"" in shell, "Darwin ARM64 must map to aarch64 release assets")
    require('VERSION="$INPUT_VERSION"' in shell, "version input must select the release")
    require("invalid KeyWatch release version" in shell, "release version must be validated before filesystem/URL use")
    require("$RUNNER_TEMP/keywatch" in shell, "binary/config install must stay under RUNNER_TEMP")
    require("KEYWATCH_CONFIG_PATH=$config_path" in shell, "detectors config path must be persisted")
    require("echo \"$bin_dir\" >> \"$GITHUB_PATH\"" in shell, "binary dir must be published via GITHUB_PATH")
    require("export PATH=\"$bin_dir:$PATH\"" in shell, "binary dir must be on current-step PATH")
    require("releases/download/$VERSION/detectors.toml" in shell, "detectors.toml must come from the exact release")
    require("$binary_url.sha256" in shell, "binary checksum must come from the exact release")
    require("$config_url.sha256" in shell, "config checksum must come from the exact release")
    require("binary checksum verification failed" in shell, "binary checksum mismatch must fail installation")
    require("detectors.toml checksum verification failed" in shell, "config checksum mismatch must fail installation")
    require("keywatch_args+=(--output \"$report_path\")" in shell, "scan must always request a JSON report")
    require("rm -f -- \"$report_path\"" in shell, "stale reports must be removed before scanning")
    require("scan_status=$?" in shell, "scanner exit status must be captured")
    require("echo \"exit_code=$scan_status\"" in shell, "scanner status must be written to outputs")
    require("findings_count=\"unknown\"" in shell, "missing/malformed reports must not default to zero findings")
    require("jq -e '.findings | type == \"array\"'" in shell, "findings count must validate JSON report shape")
    require("action_status=$scan_status" in shell, "action status must preserve scanner status by default")
    require("action_status=2" in shell, "missing/malformed report after scanner success must fail integration")
    require("GITHUB_STEP_SUMMARY" in shell, "action must append a Markdown summary")
    require("exit \"$action_status\"" in shell, "action must exit with scanner or integration failure status")
    require("Windows runners are not supported" in shell, "Windows must not be implied as supported")

    require(len(blocks) >= 2, "scan run block missing")
    run_install_scenarios(blocks[0])
    run_scan_scenarios(blocks[1])
    run_release_scenario(ROOT)
    validate_workflows()

    print(f"validated {ACTION.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
