"""Measure synthetic scan workloads without keeping generated fixtures."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def measure(binary: Path, directory: Path, name: str, args: list[str]) -> dict:
    command = [str(binary), "scan", "--no-config-discovery", "--no-baseline-discovery",
               "--verbose", "--fail-on-unscannable", *args]
    if sys.platform == "darwin":
        command = ["/usr/bin/time", "-l", *command]
    elif sys.platform.startswith("linux"):
        command = ["/usr/bin/time", "-v", *command]
    start = time.perf_counter()
    result = subprocess.run(command, cwd=directory, capture_output=True, text=True, check=False)
    elapsed = time.perf_counter() - start
    report = json.loads(result.stdout)
    peak = re.search(r"(\d+)\s+maximum resident set size", result.stderr)
    linux_peak = re.search(r"Maximum resident set size \(kbytes\): (\d+)", result.stderr)
    return {
        "scenario": name,
        "seconds": round(elapsed, 3),
        "peak_rss_bytes": int(peak[1]) if peak else int(linux_peak[1]) * 1024 if linux_peak else None,
        "exit_code": result.returncode,
        "files_scanned": report["files_scanned"],
        "coverage": report["coverage"],
        "findings": len(report["findings"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--files", type=int, default=2000)
    parser.add_argument("--lines", type=int, default=200)
    args = parser.parse_args()
    if args.files < 1 or args.lines < 1:
        parser.error("File and line counts must be positive")
    binary = args.binary.resolve(strict=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="keywatch-benchmark-") as temporary:
        directory = Path(temporary)
        tree = directory / "tree"
        tree.mkdir()
        content = "// ordinary fixture line\n" * args.lines
        for index in range(args.files):
            (tree / f"fixture-{index}.rs").write_text(content, encoding="utf-8")
        results.append(measure(binary, directory, "many-small-files", ["tree"]))
        (directory / "long-line.txt").write_text("x" * (1024 * 1024 + 1), encoding="utf-8")
        results.append(measure(binary, directory, "oversized-line", ["long-line.txt"]))
        (directory / "many-findings.txt").write_text("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n" * 10001, encoding="utf-8")
        results.append(measure(binary, directory, "finding-budget", ["many-findings.txt"]))
        (directory / "rejected.txt").write_text("ordinary\n" * 100000, encoding="utf-8")
        (directory / "rule.toml").write_text("[[rules]]\nname = 'RejectedFixture'\nfinding_type = 'Fixture'\npattern = '\\n'\nallowlist = ['\\n']\n", encoding="utf-8")
        results.append(measure(binary, directory, "rejected-multiline", ["rejected.txt", "--config", "rule.toml"]))
    print(json.dumps({"platform": sys.platform, "files": args.files, "lines_per_file": args.lines, "results": results}, indent=2))
    expected = [(0, "COMPLETE"), (1, "INCOMPLETE"), (1, "INCOMPLETE"), (0, "COMPLETE")]
    if any((row["exit_code"], row["coverage"]) != expectation for row, expectation in zip(results, expected)):
        raise SystemExit("A workload did not meet its coverage contract")


if __name__ == "__main__":
    main()
