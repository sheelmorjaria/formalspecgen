"""Security assessment combining formal VC classification with optional Semgrep SAST."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from . import cwe_registry
from .verify import verify

from . import config

_SECURITY_DIR = config.resource_path("security")
_SAST_CONFIGS = {".java": _SECURITY_DIR / "java_custom.yml",
                 ".c": _SECURITY_DIR / "c_custom.yml",
                 ".h": _SECURITY_DIR / "c_custom.yml",
                 ".cpp": _SECURITY_DIR / "c_custom.yml",
                 ".cc": _SECURITY_DIR / "c_custom.yml"}


def map_formal_failure_to_cwe(verifier: str, failure_text: str) -> dict[str, str]:
    """Map native prover diagnostics through the CWE manifest's trigger table."""
    return cwe_registry.native_trigger_findings(verifier, failure_text)


def map_formal_vcs(output: str) -> list[dict[str, str]]:
    """Map recognized formal verification-condition labels through the CWE manifest."""
    findings: list[dict[str, str]] = []
    for entry in cwe_registry.entries().values():
        for label in entry.vc_labels:
            if label in output:
                findings.append(entry.formal_finding(label))
        if (entry.synthesis_trigger and entry.synthesis_trigger in output.lower()
                and not any(item["cwe"] == entry.cwe_id for item in findings)):
            findings.append(entry.formal_finding(
                next(iter(entry.vc_labels), "LoopTermination")))
        if (entry.variants and any(label in output for label in entry.vc_labels)):
            for variant_name in entry.variants:
                variant = cwe_registry.variant_entry(entry.cwe_id, variant_name)
                marker = {"underflow": "underflow"}.get(variant_name)
                if variant is not None and marker and marker in output.lower():
                    findings.append({"source": "openjml_esc",
                                     "vc": next(iter(entry.vc_labels)),
                                     "cwe": variant.cwe_id, "severity": variant.severity,
                                     "description": variant.name})
    # OpenJML versions differ in the exact null-dereference label. Preserve the
    # security classification when the diagnostic is phrased descriptively.
    lowered = output.lower()
    for entry in cwe_registry.entries().values():
        if (entry.fuzzy_diagnostics
                and any(marker in lowered for marker in entry.fuzzy_diagnostics)
                and not any(item["cwe"] == entry.cwe_id for item in findings)):
            findings.append({"source": "openjml_esc", "vc": "PossiblyNull",
                             "cwe": entry.cwe_id, "severity": entry.severity,
                             "description": entry.name})
    return findings


def sast_config_for(source: str | Path) -> str | None:
    """Language-scoped Semgrep config; unsupported languages skip SAST."""
    suffix = Path(source).suffix.lower()
    config = _SAST_CONFIGS.get(suffix)
    if config is None or not config.exists():
        return None
    return str(config)


def run_semgrep(source: str | Path, *, timeout: int = 60,
                config: str | Path | None = None) -> dict[str, Any]:
    """Run the language-scoped Semgrep rules and normalize JSON output."""
    if config is not None:
        selected_config = str(config)
        if not Path(selected_config).exists():
            selected_config = "p/java"  # preserve the explicit-config registry fallback
    else:
        selected_config = sast_config_for(source)
        if not selected_config:
            return {"status": "SKIPPED", "tool": "semgrep",
                    "message": "no SAST rules configured for this language"}
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
        entry = cwe_registry.by_rule_id(rule_id)
        findings.append({"tool": "semgrep", "rule_id": result.get("check_id"),
                         "line": result.get("start", {}).get("line"),
                         "severity": extra.get("severity", "INFO"),
                         "message": extra.get("message", ""),
                         "cwe": entry.cwe_id if entry else None,
                         "unmapped_rule_id": entry is None})
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
            "formal_cwes_mitigated": cwe_registry.mitigated_formal_cwes()
            if formal_verified else [],
            "sast": sast, "sast_findings": sast_findings,
            "security_scope": "Formal memory/arithmetic obligations plus configured Semgrep rules; external I/O and unmodeled vulnerabilities are not assessed.",
            "behavior_equivalence_proved": False}
