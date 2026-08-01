#!/usr/bin/env python3
"""Static regression checks for the KeyWatch composite action."""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github" / "actions" / "keywatch-scan" / "action.yml"


class ScanScenario(NamedTuple):
    name: str
    paths: str
    args: str
    scanner_exit: int
    report_mode: str
    expected_status: int
    expected_output: tuple[str, ...] = ()
    expected_capture: tuple[str, ...] = ()
    forbidden_capture: tuple[str, ...] = ()
    expected_stderr: tuple[str, ...] = ()
    expected_summary: tuple[str, ...] = ()
    preseed_report: bool = False
    config: str = ""


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


def write_keywatch_stub(bin_dir: Path) -> Path:
    stub = bin_dir / "key-watch"
    stub.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n: > \"$KEYWATCH_CAPTURE\"\n"
        "for arg in \"$@\"; do printf '%s\\n' \"$arg\" >> \"$KEYWATCH_CAPTURE\"; done\n"
        "out=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--output\" ]; then shift; out=\"$1\"; fi\n"
        "  shift || true\ndone\ncase \"$KEYWATCH_REPORT_MODE\" in\n"
        "  valid) printf '%s\\n' '{\"findings\":[{},{}]}' > \"$out\" ;;\n"
        "  malformed) printf '%s\\n' 'not-json' > \"$out\" ;;\n  missing) ;;\n  *) exit 99 ;;\nesac\n"
        "exit \"$KEYWATCH_STUB_EXIT\"\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub


def run_scan_scenarios(scan_block: str) -> None:
    scenarios = (
        ScanScenario("glob-expands", "scan/*.txt", "", 0, "valid", 0, ("exit_code=0", "findings_count=2"), ("--no-config-discovery", "scan/match.txt"), ("scan/*.txt", "--verbose")),
        ScanScenario("explicit-config", ".", "", 0, "valid", 0, expected_capture=("--no-config-discovery\n", "--config\ntrusted.toml\n"), config="trusted.toml"),
        ScanScenario("semicolon-literal", "literal;touch_pwned", "", 0, "valid", 0, expected_capture=("literal;touch_pwned",)),
        ScanScenario("path-option-is-literal", "--verbose", "", 0, "valid", 0, expected_capture=("--\n--verbose\n",)),
        ScanScenario("format-long-value-rejected", ".", "--format sarif", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("config-passthrough-rejected", ".", "--config .keywatch.toml", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("verbose-long-value-rejected", ".", "--verbose=true", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("verbose-compact-short-rejected", ".", "-vv", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("verbose-mode-long-allowed", ".", "--verbose-mode", 0, "valid", 0, expected_capture=("--verbose-mode",)),
        ScanScenario("scanner-nonzero-propagates", ".", "", 1, "valid", 1, ("exit_code=1", "findings_count=2")),
        ScanScenario("missing-report-zero-fails", ".", "", 0, "missing", 2, ("exit_code=0", "findings_count=unknown"), expected_stderr=("JSON report is missing",), expected_summary=("| Report | missing |",)),
        ScanScenario("stale-report-ignored", ".", "", 0, "missing", 2, ("exit_code=0", "findings_count=unknown"), expected_stderr=("JSON report is missing",), expected_summary=("| Report | missing |",), preseed_report=True),
    )

    with tempfile.TemporaryDirectory(prefix="keywatch-action-") as raw_tmp:
        tmp = Path(raw_tmp)
        scan_script = tmp / "scan.sh"
        scan_script.write_text(scan_block, encoding="utf-8")
        scan_script.chmod(0o755)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        write_keywatch_stub(bin_dir)

        for scenario in scenarios:
            workspace = tmp / scenario.name
            workspace.mkdir()
            (workspace / "scan").mkdir()
            (workspace / "scan" / "match.txt").write_text("match", encoding="utf-8")
            (workspace / "scan" / "other.md").write_text("other", encoding="utf-8")
            (workspace / "detectors.toml").write_text("", encoding="utf-8")
            if scenario.preseed_report:
                (workspace / "keywatch-report.json").write_text(
                    '{"findings":[{}, {}, {}, {}]}\n',
                    encoding="utf-8",
                )

            env = {
                "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
                "KEYWATCH_CONFIG_PATH": str(workspace / "detectors.toml"),
                "GITHUB_OUTPUT": str(workspace / "output"),
                "GITHUB_STEP_SUMMARY": str(workspace / "summary"),
                "RUNNER_TEMP": str(workspace),
                "INPUT_PATHS": scenario.paths,
                "INPUT_ARGS": scenario.args,
                "INPUT_EXIT_MODE": "strict",
                "INPUT_OUTPUT": "",
                "INPUT_VERBOSE": "false",
                "INPUT_CONFIG": scenario.config,
                "KEYWATCH_CAPTURE": str(workspace / "capture"),
                "KEYWATCH_STUB_EXIT": str(scenario.scanner_exit),
                "KEYWATCH_REPORT_MODE": scenario.report_mode,
            }
            result = subprocess.run(
                ["bash", str(scan_script)],
                check=False,
                cwd=workspace,
                env=env,
                text=True,
                capture_output=True,
            )
            require(
                result.returncode == scenario.expected_status,
                f"{scenario.name}: got status {result.returncode}, "
                f"expected {scenario.expected_status}; stderr={result.stderr!r}",
            )

            output = (workspace / "output").read_text(encoding="utf-8") if (workspace / "output").exists() else ""
            summary = (workspace / "summary").read_text(encoding="utf-8") if (workspace / "summary").exists() else ""
            capture = (workspace / "capture").read_text(encoding="utf-8") if (workspace / "capture").exists() else ""
            for expected in scenario.expected_output:
                require(expected in output, f"{scenario.name}: missing output {expected!r}")
            for expected in scenario.expected_capture:
                require(expected in capture, f"{scenario.name}: missing argv {expected!r}")
            for forbidden in scenario.forbidden_capture:
                require(forbidden not in capture, f"{scenario.name}: forbidden argv {forbidden!r}")
            for expected in scenario.expected_stderr:
                require(expected in result.stderr, f"{scenario.name}: missing stderr {expected!r}")
            for expected in scenario.expected_summary:
                require(expected in summary, f"{scenario.name}: missing summary {expected!r}")


def main() -> int:
    text = ACTION.read_text(encoding="utf-8")
    blocks = run_blocks(text)
    shell = "\n".join(blocks)

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
    require("VERSION=$(jq -er '.tag_name'" in shell, "latest must resolve to a concrete release tag")
    require("invalid KeyWatch version/tag" in shell, "release tag must be validated before filesystem/URL use")
    require("$RUNNER_TEMP/keywatch" in shell, "binary/config install must stay under RUNNER_TEMP")
    require("KEYWATCH_CONFIG_PATH=$config_path" in shell, "detectors config path must be persisted")
    require("echo \"$bin_dir\" >> \"$GITHUB_PATH\"" in shell, "binary dir must be published via GITHUB_PATH")
    require("export PATH=\"$bin_dir:$PATH\"" in shell, "binary dir must be on current-step PATH")
    require("config_url=\"https://raw.githubusercontent.com/$REPO/$VERSION/detectors.toml\"" in shell, "detectors.toml must come from the exact tag")
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
    run_scan_scenarios(blocks[1])

    print(f"validated {ACTION.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
