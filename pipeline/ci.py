# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""GitHub Actions/CLI verifier emitting native workflow annotations."""
import argparse
import json
import os
import subprocess
from dataclasses import asdict
from pathlib import Path

from .parse_check import parse_check
from .parse_vcs import parse_vcs
from .verify import verify, classify, has_dropped_vc
from .spec_lint import lint_spec
from .explain_vc import explain_vc


def changed_java(base: str) -> list[Path]:
    process = subprocess.run(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"],
                             capture_output=True, text=True)
    if process.returncode != 0:
        raise RuntimeError(process.stderr.strip() or "git diff failed")
    return [Path(line) for line in process.stdout.splitlines()
            if line.endswith((".java", ".jml")) and Path(line).exists()]


def check_files(files: list[Path], mode: str = "check") -> dict:
    rows = []
    failed = False
    for file in files:
        exit_code, output = verify(file, mode=mode)
        status = classify(exit_code)
        if mode == "esc" and status == "VERIFIED" and has_dropped_vc(output):
            status = "VACUOUS_VERIFIED"
        diagnostics = parse_vcs(output) if mode == "esc" else parse_check(output)
        warnings = lint_spec(file.read_text())
        if status != "VERIFIED":
            failed = True
        for diagnostic in diagnostics:
            explanation = explain_vc(diagnostic.category, diagnostic.detail or diagnostic.raw)
            _annotation("error", file, diagnostic.line,
                        diagnostic.detail or diagnostic.raw, explanation["advice"])
        for warning in warnings:
            _annotation("warning", file, warning["line"], warning["message"], warning["advice"])
        rows.append({"file": str(file), "status": status, "exit_code": exit_code,
                     "diagnostics": [asdict(item) for item in diagnostics], "warnings": warnings})
    return {"status": "FAILED" if failed else "VERIFIED", "mode": mode,
            "files": rows, "checked": len(rows)}


def _annotation(level: str, file: Path, line: int, title: str, advice: str) -> None:
    clean = lambda value: str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} file={clean(file)},line={max(1, line)},title=FormalSpec::{clean(title)}%0A{clean(advice)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify changed JML files and emit GitHub annotations")
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--base", default=None, help="base git ref for changed-file discovery")
    parser.add_argument("--mode", choices=["check", "esc"], default="check")
    parser.add_argument("--report", type=Path, default=Path("formalspec-report.json"))
    args = parser.parse_args()
    files = args.files or changed_java(args.base or os.environ.get("GITHUB_BASE_REF", "HEAD^"))
    result = check_files(files, args.mode)
    args.report.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"FormalSpec: {result['status']} ({result['checked']} file(s), mode={args.mode})")
    raise SystemExit(1 if result["status"] == "FAILED" else 0)


if __name__ == "__main__":
    main()
