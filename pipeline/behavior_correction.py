"""Spec-driven behavior correction with fail-closed formal evidence."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .jml_io import extract_clauses
from .llm import _chat_fn, strip_fence
from .verify import verify


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strengthening_guidance(cwe: str) -> str:
    if cwe == "CWE-125":
        return ("Add conditional postconditions: valid indices return arr[index]; invalid "
                "indices return -1. Add the runtime bounds guard required to satisfy them.")
    if cwe == "CWE-476":
        return "Specify and implement explicit null handling, or a signals (NullPointerException) clause."
    return "Define explicit safe behavior for the reported weakness and preserve the public method signatures."


def correct_behavior(target: str | Path, cwe: str, out_dir: str | Path = "corrections",
                     *, provider: str = "ollama", model: str | None = None,
                     max_attempts: int = 3) -> dict[str, Any]:
    source_path = Path(target)
    if not source_path.is_file():
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(source_path)}
    original = source_path.read_text(encoding="utf-8")
    guidance = _strengthening_guidance(cwe)
    try:
        raw, _, _ = _chat_fn(provider)([
            {"role": "system", "content": "You write precise JML contracts without changing Java APIs."},
            {"role": "user", "content": f"Rewrite only the JML contract for CWE {cwe}. {guidance}\n"
             "Preserve the class and method signatures and output one complete Java file.\n\n" + original}],
            model, 0.1)
        strengthened = strip_fence(raw)
    except Exception as exc:
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "spec_strengthening_failed", "message": str(exc)}
    destination = Path(out_dir); destination.mkdir(parents=True, exist_ok=True)
    strengthened_path = destination / f"{source_path.stem}.strengthened.java"
    corrected_path = destination / source_path.name
    strengthened_path.write_text(strengthened, encoding="utf-8")
    baseline_contract = extract_clauses(original)
    strengthened_contract = extract_clauses(strengthened)
    evidence: dict[str, Any] = {
        "target": str(source_path), "mitigated_cwe": cwe,
        "baseline_contract_hash": _digest("\n".join(sorted(baseline_contract))),
        "strengthened_contract_hash": _digest("\n".join(sorted(strengthened_contract))),
        "strengthened_file": str(strengthened_path), "attempts": 0,
    }
    for attempt in range(1, max_attempts + 1):
        evidence["attempts"] = attempt
        exit_code, output = verify(strengthened_path, mode="esc")
        if exit_code == 0:
            corrected = strengthened
        else:
            try:
                raw, _, _ = _chat_fn(provider)([
                    {"role": "system", "content": "You repair Java code to satisfy its JML contract."},
                    {"role": "user", "content": f"Fix this CWE-{cwe} implementation. Add defensive runtime "
                     f"guards and preserve its API. OpenJML output:\n{output[-4000:]}\n\n{strengthened}"}],
                    model, 0.1)
                corrected = strip_fence(raw)
            except Exception as exc:
                evidence.update({"code": "patch_generation_failed", "message": str(exc)})
                break
        corrected_path.write_text(corrected, encoding="utf-8")
        final_exit, final_output = verify(corrected_path, mode="esc")
        if final_exit == 0:
            evidence.update({"status": "BEHAVIOR_CORRECTION_VERIFIED",
                             "claim": "BEHAVIOR_CORRECTION_VERIFIED",
                             "corrected_implementation_hash": _digest(corrected),
                             "corrected_file": str(corrected_path),
                             "formal_proof": "DEDUCTIVE_PROOF"})
            return evidence
    evidence.update({"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                     "code": "corrected_source_not_verified",
                     "formal_output": (final_output if 'final_output' in locals() else output)[-4000:]})
    return evidence
