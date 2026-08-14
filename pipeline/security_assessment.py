"""Security assessment combining formal VC classification with optional Semgrep SAST."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .verify import verify


FORMAL_CWE_MAP = {
    "ArithmeticOperationRange": ("CWE-190", "HIGH", "Integer Overflow or Wraparound"),
    "PossiblyNegativeIndex": ("CWE-125", "HIGH", "Out-of-bounds Read"),
    "PossiblyTooLargeIndex": ("CWE-125", "HIGH", "Out-of-bounds Read"),
    "UndefinedNegativeIndex": ("CWE-125", "HIGH", "Out-of-bounds Read"),
    "ArrayStore": ("CWE-787", "HIGH", "Out-of-bounds Write"),
    "NullPointer": ("CWE-476", "HIGH", "NULL Pointer Dereference"),
    "PossiblyNull": ("CWE-476", "HIGH", "NULL Pointer Dereference"),
}


def map_formal_vcs(output: str) -> list[dict[str, str]]:
    """Map recognized formal verification-condition labels to CWE evidence."""
    findings: list[dict[str, str]] = []
    for label, (cwe, severity, description) in FORMAL_CWE_MAP.items():
        if label in output:
            findings.append({"source": "openjml_esc", "vc": label, "cwe": cwe,
                             "severity": severity, "description": description})
    return findings


def run_semgrep(source: str | Path, *, timeout: int = 60) -> dict[str, Any]:
    """Run Semgrep's Java rules and normalize JSON output."""
    try:
        process = subprocess.run(["semgrep", "--config", "p/java", "--json", str(source)],
                                 capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"status": "TOOL_MISSING", "tool": "semgrep",
                "message": "semgrep is not installed"}
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "tool": "semgrep", "message": "semgrep timed out"}
    try:
        data = json.loads(process.stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "INVALID_OUTPUT", "tool": "semgrep",
                "message": (process.stderr or process.stdout)[-2000:]}
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        findings.append({"tool": "semgrep", "rule_id": result.get("check_id"),
                         "line": result.get("start", {}).get("line"),
                         "severity": extra.get("severity", "INFO"),
                         "message": extra.get("message", "")})
    return {"status": "CLEAN" if not findings else "FINDINGS", "tool": "semgrep",
            "findings": findings, "exit_code": process.returncode}


def assess_security(source: str | Path, *, run_sast: bool = True) -> dict[str, Any]:
    path = Path(source)
    if not path.is_file():
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "input_unavailable",
                "file": str(path), "message": str(path)}
    exit_code, output = verify(path, mode="esc")
    formal_findings = map_formal_vcs(output)
    formal_verified = exit_code == 0
    sast = run_semgrep(path) if run_sast else {"status": "SKIPPED", "tool": "semgrep"}
    sast_findings = sast.get("findings", [])
    blocking_sast = [item for item in sast_findings
                     if str(item.get("severity", "")).upper() in {"ERROR", "HIGH", "CRITICAL"}]
    blockers = formal_findings + blocking_sast
    if formal_verified and not blockers and sast["status"] == "CLEAN":
        status = "VERIFIED_SECURE"
    elif formal_verified and not blockers and sast["status"] == "SKIPPED":
        status = "FORMALLY_VERIFIED_SAST_SKIPPED"
    elif formal_verified and not blockers and sast["status"] in {"TOOL_MISSING", "TIMEOUT", "INVALID_OUTPUT"}:
        status = "SECURITY_ASSESSMENT_INCOMPLETE"
    else:
        status = "SECURITY_VIOLATION"
    return {"status": status, "claim": status, "file": str(path),
            "formal_verification": {"exit_code": exit_code, "verified": formal_verified,
                                     "output": output[-4000:]},
            "formal_findings": formal_findings,
            "formal_cwes_mitigated": ["CWE-125", "CWE-190", "CWE-476"]
            if formal_verified else [],
            "sast": sast, "sast_findings": sast_findings,
            "security_scope": "Formal memory/arithmetic obligations plus configured Semgrep rules; external I/O and unmodeled vulnerabilities are not assessed.",
            "behavior_equivalence_proved": False}
