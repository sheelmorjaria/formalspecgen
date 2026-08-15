"""Security assessment combining formal VC classification with optional Semgrep SAST."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .verify import verify


FORMAL_CWE_MAP = {
    "ArithmeticOperationRange": ("CWE-190", "HIGH", "Integer Overflow or Wraparound"),
    "NegativeArraySize": ("CWE-131", "HIGH", "Incorrect Calculation of Buffer Size"),
    "LoopTermination": ("CWE-835", "MEDIUM", "Infinite Loop"),
    "PossiblyNegativeIndex": ("CWE-125", "HIGH", "Out-of-bounds Read"),
    "PossiblyTooLargeIndex": ("CWE-125", "HIGH", "Out-of-bounds Read"),
    "UndefinedNegativeIndex": ("CWE-125", "HIGH", "Out-of-bounds Read"),
    "ArrayStore": ("CWE-787", "HIGH", "Out-of-bounds Write"),
    "NullPointer": ("CWE-476", "HIGH", "NULL Pointer Dereference"),
    "PossiblyNull": ("CWE-476", "HIGH", "NULL Pointer Dereference"),
}


def map_formal_failure_to_cwe(verifier: str, failure_text: str) -> dict[str, str]:
    """Map native prover diagnostics to the language-independent CWE taxonomy."""
    text = failure_text.lower()
    if verifier == "openjml":
        if "possiblynegativeindex" in text or "possiblytoolargeindex" in text:
            return {"cwe": "CWE-125", "severity": "HIGH"}
        if "arithmeticoperationrange" in text:
            return {"cwe": "CWE-191" if "underflow" in text else "CWE-190", "severity": "HIGH"}
    elif verifier == "framac":
        if "pointer_dereference" in text or "null_pointer" in text:
            return {"cwe": "CWE-476", "severity": "HIGH"}
        if "signed_overflow" in text or "unsigned_overflow" in text:
            return {"cwe": "CWE-190", "severity": "HIGH"}
    elif verifier == "prusti":
        if "precondition" in text and "index" in text:
            return {"cwe": "CWE-125", "severity": "HIGH"}
    elif verifier == "esbmc":
        if "array bounds" in text or "out of bounds" in text:
            return {"cwe": "CWE-125", "severity": "HIGH"}
        if "overflow" in text:
            return {"cwe": "CWE-190", "severity": "HIGH"}
    return {"cwe": "UNKNOWN", "severity": "LOW"}


def map_formal_vcs(output: str) -> list[dict[str, str]]:
    """Map recognized formal verification-condition labels to CWE evidence."""
    findings: list[dict[str, str]] = []
    for label, (cwe, severity, description) in FORMAL_CWE_MAP.items():
        if label in output:
            findings.append({"source": "openjml_esc", "vc": label, "cwe": cwe,
                             "severity": severity, "description": description})
    if "ArithmeticOperationRange" in output and "underflow" in output.lower():
        findings.append({"source": "openjml_esc", "vc": "ArithmeticOperationRange",
                         "cwe": "CWE-191", "severity": "HIGH",
                         "description": "Integer Underflow"})
    if "decreases" in output.lower() and not any(item["cwe"] == "CWE-835" for item in findings):
        findings.append({"source": "openjml_esc", "vc": "LoopTermination",
                         "cwe": "CWE-835", "severity": "MEDIUM",
                         "description": "Infinite Loop"})
    return findings


def run_semgrep(source: str | Path, *, timeout: int = 60,
                config: str | Path | None = None) -> dict[str, Any]:
    """Run Semgrep's Java rules and normalize JSON output."""
    selected_config = str(config or Path(__file__).resolve().parents[1] / "security" / "java_custom.yml")
    if not Path(selected_config).exists():
        selected_config = "p/java"
    try:
        process = subprocess.run(["semgrep", "--config", selected_config, "--json", str(source)],
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
        rule_id = result.get("check_id", "")
        cwe = {"CWE-22-PATH-TRAVERSAL": "CWE-22",
               "CWE-502-DESERIALIZATION": "CWE-502",
               "CWE-327-WEAK-CRYPTO": "CWE-327",
               "CWE-209-EXCEPTION-EXPOSURE": "CWE-209"}.get(rule_id)
        findings.append({"tool": "semgrep", "rule_id": result.get("check_id"),
                         "line": result.get("start", {}).get("line"),
                         "severity": extra.get("severity", "INFO"),
                         "message": extra.get("message", ""), "cwe": cwe})
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
