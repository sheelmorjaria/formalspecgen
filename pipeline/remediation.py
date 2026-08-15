"""Safe, non-destructive LLM remediation followed by formal re-verification."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .llm import _chat_fn, strip_fence
from .verify import verify


def remediate(target: str | Path, report: str | Path, out_dir: str | Path = "remediated",
              *, provider: str = "ollama", model: str | None = None) -> dict[str, Any]:
    target_path, report_path = Path(target), Path(report)
    if not target_path.is_file() or not report_path.is_file():
        return {"status": "REMEDIATION_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(target_path)}
    try:
        raw_report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "REMEDIATION_FAILED", "claim": "NO_PROOF",
                "code": "invalid_report", "message": str(exc)}
    findings = raw_report if isinstance(raw_report, list) else raw_report.get("findings", [])
    if not findings:
        return {"status": "NO_REMEDIATION_REQUIRED", "claim": "NO_PROOF",
                "target": str(target_path), "mitigated_cwes": []}
    original = target_path.read_text(encoding="utf-8")
    language = {".java": "Java/JML with //@ requires clauses",
                ".rs": "Rust/Prusti with #[requires] attributes",
                ".c": "C/ACSL with /*@ requires ... */ contracts",
                ".h": "C/ACSL with /*@ requires ... */ contracts",
                ".cpp": "C++ with the native contract syntax supported by the configured verifier",
                ".cc": "C++ with the native contract syntax supported by the configured verifier"}.get(
                    target_path.suffix.lower(), "the source language's supported contract syntax")
    details = "\n".join(f"- {item.get('cwe', 'UNKNOWN')}: {item.get('message', item.get('description', ''))}"
                         for item in findings)
    guidance = ""
    if any(item.get("cwe") == "CWE-78" for item in findings):
        guidance = " For CWE-78, avoid shell interpretation, use a fixed executable plus an argument list, and whitelist arguments."
    if any(item.get("cwe") == "CWE-79" for item in findings):
        guidance += " For CWE-79, HTML-escape untrusted output before rendering."
    if any(item.get("cwe") == "CWE-326" for item in findings):
        guidance += " For CWE-326, enforce RSA key sizes of at least 2048 bits."
    if any(item.get("cwe") == "CWE-732" for item in findings):
        guidance += " For CWE-732, use least-privilege file permissions and avoid world-writable modes."
    prompt = (f"You are a defensive security engineer. Patch this {language} source to address "
              "the listed findings. Preserve the public class and method signatures. Add precise "
              "JML requires/ensures clauses and safe handling where appropriate. Do not use "
              "loop_assignable (OpenJML 21 rejects it). Return only one complete Java file.\n\n"
              f"Findings:\n{details}\n\nSource:\n{original}{guidance}")
    try:
        raw, used_model, usage = _chat_fn(provider)([
            {"role": "system", "content": "You produce defensive, formally verifiable Java patches."},
            {"role": "user", "content": prompt}], model, 0.2)
        patched = strip_fence(raw)
    except Exception as exc:
        return {"status": "REMEDIATION_FAILED", "claim": "NO_PROOF",
                "code": "patch_generation_failed", "message": str(exc)}
    destination = Path(out_dir) / target_path.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(patched, encoding="utf-8")
    exit_code, output = verify(destination, mode="esc")
    cwes = sorted({item.get("cwe") for item in findings if item.get("cwe")})
    if exit_code != 0:
        return {"status": "REMEDIATION_FAILED", "claim": "NO_PROOF",
                "code": "patched_source_not_verified", "target": str(target_path),
                "patched_file": str(destination), "mitigated_cwes": cwes,
                "formal_output": output[-4000:], "poc_status": "NOT_EXECUTED"}
    return {"status": "REMEDIATION_VERIFIED", "claim": "REMEDIATION_VERIFIED",
            "target": str(target_path), "patched_file": str(destination),
            "mitigated_cwes": cwes, "formal_proof": "DEDUCTIVE_PROOF",
            "formal_exit_code": exit_code, "model": used_model, "usage": usage,
            "poc_status": "NOT_EXECUTED",
            "disclaimer": "The patched copy passed ESC; PoCs were not executed and external I/O is unassessed."}
