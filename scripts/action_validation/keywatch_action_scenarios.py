import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple


class InstallScenario(NamedTuple):
    name: str
    tampered_asset: str
    expected_status: int
    expected_stderr: str = ""


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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_install_fixtures(root: Path, tampered_asset: str) -> tuple[Path, Path]:
    assets = root / "assets"
    assets.mkdir()
    binary = assets / "keywatch-linux-x86_64"
    config = assets / "detectors.toml"
    write_executable(binary, "#!/usr/bin/env bash\nprintf '%s\\n' 'key-watch 1.1.0'\n")
    config.write_text("[[detectors]]\nname = 'fixture'\n", encoding="utf-8")
    for asset in (binary, config):
        (assets / f"{asset.name}.sha256").write_text(
            f"{checksum(asset)}  {asset.name}\n",
            encoding="utf-8",
        )
    if tampered_asset:
        (assets / tampered_asset).write_text("tampered\n", encoding="utf-8")

    tools = root / "tools"
    tools.mkdir()
    write_executable(
        tools / "curl",
        "#!/usr/bin/env bash\nset -euo pipefail\nurl=''\nout=''\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    -o) out=\"$2\"; shift 2 ;;\n"
        "    https://*) url=\"$1\"; shift ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\ncp \"$KEYWATCH_ASSET_DIR/${url##*/}\" \"$out\"\n",
    )
    write_executable(tools / "sha256sum", "#!/usr/bin/env bash\nshasum -a 256 \"$1\"\n")
    return assets, tools


def run_install_scenarios(install_block: str) -> None:
    scenarios = (
        InstallScenario("verified-assets", "", 0),
        InstallScenario(
            "tampered-binary",
            "keywatch-linux-x86_64",
            1,
            "binary checksum verification failed",
        ),
        InstallScenario(
            "tampered-config",
            "detectors.toml",
            1,
            "detectors.toml checksum verification failed",
        ),
    )
    with tempfile.TemporaryDirectory(prefix="keywatch-install-") as raw_tmp:
        root = Path(raw_tmp)
        script = root / "install.sh"
        write_executable(script, install_block)
        for scenario in scenarios:
            scenario_root = root / scenario.name
            scenario_root.mkdir()
            assets, tools = write_install_fixtures(scenario_root, scenario.tampered_asset)
            env = {
                "PATH": f"{tools}:{os.environ.get('PATH', '')}",
                "KEYWATCH_ASSET_DIR": str(assets),
                "INPUT_VERSION": "1.1.0",
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "RUNNER_TEMP": str(scenario_root / "runner"),
                "GITHUB_PATH": str(scenario_root / "github-path"),
                "GITHUB_ENV": str(scenario_root / "github-env"),
                "GITHUB_TOKEN": "",
            }
            result = subprocess.run(
                ["bash", str(script)],
                check=False,
                env=env,
                text=True,
                capture_output=True,
            )
            require(
                result.returncode == scenario.expected_status,
                f"{scenario.name}: got status {result.returncode}, expected "
                f"{scenario.expected_status}; stderr={result.stderr!r}",
            )
            require(
                scenario.expected_stderr in result.stderr,
                f"{scenario.name}: missing stderr {scenario.expected_stderr!r}",
            )
            if scenario.expected_status == 0:
                config_env = (scenario_root / "github-env").read_text(encoding="utf-8")
                require("KEYWATCH_CONFIG_PATH=" in config_env, "verified install must publish detector config")


def write_keywatch_stub(bin_dir: Path) -> None:
    write_executable(
        bin_dir / "key-watch",
        "#!/usr/bin/env bash\nset -euo pipefail\n: > \"$KEYWATCH_CAPTURE\"\n"
        "for arg in \"$@\"; do printf '%s\\n' \"$arg\" >> \"$KEYWATCH_CAPTURE\"; done\n"
        "out=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--output\" ]; then shift; out=\"$1\"; fi\n"
        "  shift || true\ndone\ncase \"$KEYWATCH_REPORT_MODE\" in\n"
        "  valid) printf '%s\\n' '{\"findings\":[{},{}]}' > \"$out\" ;;\n"
        "  malformed) printf '%s\\n' 'not-json' > \"$out\" ;;\n  missing) ;;\n  *) exit 99 ;;\nesac\n"
        "exit \"$KEYWATCH_STUB_EXIT\"\n",
    )


def run_scan_scenarios(scan_block: str) -> None:
    scenarios = (
        ScanScenario(
            "glob-expands",
            "scan/*.txt",
            "",
            0,
            "valid",
            0,
            ("exit_code=0", "findings_count=2"),
            ("--no-config-discovery", "scan/match.txt"),
            ("scan/*.txt", "--verbose"),
        ),
        ScanScenario(
            "explicit-config",
            ".",
            "",
            0,
            "valid",
            0,
            expected_capture=("--no-config-discovery\n", "--config\ntrusted.toml\n"),
            config="trusted.toml",
        ),
        ScanScenario("semicolon-literal", "literal;touch_pwned", "", 0, "valid", 0, expected_capture=("literal;touch_pwned",)),
        ScanScenario("path-option-is-literal", "--verbose", "", 0, "valid", 0, expected_capture=("--\n--verbose\n",)),
        ScanScenario("format-long-value-rejected", ".", "--format sarif", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("config-passthrough-rejected", ".", "--config .keywatch.toml", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("verbose-long-value-rejected", ".", "--verbose=true", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("verbose-compact-short-rejected", ".", "-vv", 0, "valid", 1, expected_stderr=("managed by action inputs",)),
        ScanScenario("verbose-mode-long-allowed", ".", "--verbose-mode", 0, "valid", 0, expected_capture=("--verbose-mode",)),
        ScanScenario("scanner-nonzero-propagates", ".", "", 1, "valid", 1, ("exit_code=1", "findings_count=2")),
        ScanScenario(
            "missing-report-zero-fails",
            ".",
            "",
            0,
            "missing",
            2,
            ("exit_code=0", "findings_count=unknown"),
            expected_stderr=("JSON report is missing",),
            expected_summary=("| Report | missing |",),
        ),
        ScanScenario(
            "stale-report-ignored",
            ".",
            "",
            0,
            "missing",
            2,
            ("exit_code=0", "findings_count=unknown"),
            expected_stderr=("JSON report is missing",),
            expected_summary=("| Report | missing |",),
            preseed_report=True,
        ),
    )
    with tempfile.TemporaryDirectory(prefix="keywatch-action-") as raw_tmp:
        tmp = Path(raw_tmp)
        scan_script = tmp / "scan.sh"
        write_executable(scan_script, scan_block)
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
                (workspace / "keywatch-report.json").write_text('{"findings":[{}, {}, {}, {}]}\n', encoding="utf-8")
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
                f"{scenario.name}: got status {result.returncode}, expected "
                f"{scenario.expected_status}; stderr={result.stderr!r}",
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
