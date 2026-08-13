# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed AWS Kani bounded verification for explicit Rust proof harnesses."""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import config

_HARNESS = re.compile(r"#\s*\[\s*kani::proof\s*\]\s*(?:pub\s+)?fn\s+(\w+)")
_PRUSTI = re.compile(r"(?m)^\s*#\[(?:requires|ensures|pure|predicate)(?:\([^\n]*\))?\]\s*$")
_VERIFIED_SUMMARY = re.compile(r"successfully verified (\d+) of (\d+) properties", re.I)
_SUCCESS_CHECK = re.compile(r"(?m)^\s*Check \d+:.*Status: SUCCESS\s*$")


def kani_harnesses(code: str) -> list[str]:
    return sorted(set(_HARNESS.findall(code)))


def parse_kani_diagnostics(output: str) -> list[dict]:
    findings = []
    for match in re.finditer(r"(?m)^(?:VERIFICATION:-\s*)?FAILED(?:\s*:\s*|\s+)(.+)$", output):
        findings.append({"category": "KaniProperty", "detail": match.group(1).strip()})
    for match in re.finditer(r"(?m)^\s*Location:\s+(.+?):(\d+):?", output):
        findings.append({"category": "KaniLocation", "file": match.group(1),
                         "line": int(match.group(2)), "detail": match.group(0).strip()})
    return findings


def verified_property_count(output: str) -> int | None:
    """Count properties Kani actually checked; None when the output carries no evidence."""
    summary = _VERIFIED_SUMMARY.search(output)
    if summary:
        return int(summary.group(1))
    successes = _SUCCESS_CHECK.findall(output)
    return len(successes) if successes else None


def verify_kani(code: str, timeout: int | None = None) -> dict:
    harnesses = kani_harnesses(code)
    if not harnesses:
        return {"status": "HARNESS_REQUIRED", "exit_code": 2, "harnesses": [],
                "claim": "NO_PROOF", "bounded": True,
                "message": "Add and human-review at least one #[kani::proof] harness."}
    binary = shutil.which(config.KANI_BIN)
    if not binary:
        return {"status": "TOOL_MISSING", "exit_code": 127, "harnesses": harnesses,
                "claim": "NO_PROOF", "bounded": True,
                "message": f"Kani executable not found: {config.KANI_BIN}"}
    cleaned = re.sub(r"(?m)^\s*use\s+prusti_contracts::\*;\s*$", "", code)
    cleaned = _PRUSTI.sub("", cleaned)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src").mkdir()
        (root / "src" / "lib.rs").write_text(cleaned, encoding="utf-8")
        (root / "Cargo.toml").write_text(
            '[package]\nname="formalspecgen_kani"\nversion="0.0.0"\nedition="2021"\n',
            encoding="utf-8")
        # Managed Marketplace installations use Kani's reviewed release bundle and
        # invoke kani-driver directly. Developer installations commonly configure
        # Cargo, whose equivalent command is `cargo kani --tests`.
        command = ([binary, "--tests"] if Path(binary).name in {"kani-driver", "kani-driver.exe"}
                   else [binary, "kani", "--tests"])
        try:
            process = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                     timeout=timeout or config.KANI_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124, "harnesses": harnesses,
                    "claim": "NO_PROOF", "bounded": True}
        except OSError as exc:
            return {"status": "TOOL_ERROR", "exit_code": 127, "harnesses": harnesses,
                    "claim": "NO_PROOF", "bounded": True, "message": str(exc)}
    output = ((process.stdout or "") + (process.stderr or "")).strip()
    status = "VERIFIED" if process.returncode == 0 else "VERIFY_FAILED"
    checked = verified_property_count(output) if process.returncode == 0 else None
    claim = "BOUNDED_RUST_EVIDENCE" if status == "VERIFIED" else "NO_PROOF"
    result = {"status": status, "exit_code": process.returncode, "harnesses": harnesses,
              "claim": claim, "bounded": True, "verified_properties": checked,
              "command": command, "diagnostics": parse_kani_diagnostics(output),
              "output": output[-12000:],
              "disclaimer": "Kani explored the reviewed harness within configured bounds; this is not deductive Prusti proof."}
    if status == "VERIFIED" and not checked:
        # Exit 0 alone is not bounded evidence: mirror Frama-C's proved-goals guard
        # and require at least one property Kani actually checked.
        result["status"] = "VACUOUS_VERIFIED"
        result["claim"] = "NO_PROOF"
        result["vacuity_note"] = (
            "Kani exited 0 but reported no successfully checked property; "
            "no bounded obligation was exercised")
    return result
