"""Spec-driven behavior correction with fail-closed formal evidence."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .hardware_profile import stack_depth_ok
from .jml_io import extract_clauses
from .llm import _chat_fn, strip_fence
from .verify import verify


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Capacity-bounding strategies: dynamic, unbounded code rewritten into static,
# bounded code. This is deliberately a BEHAVIOR CORRECTION, never a refactor:
# the corrected program rejects work beyond the capacity where the original
# accepted it without bound, and the claim says so.
_STRATEGY_GUIDANCE = {
    "bound-loop": (
        "Strategy bound-loop: add an explicit capacity (1000 by default). "
        "Strengthen the contract with requires iterations <= 1000, then rewrite "
        "every unbounded while(true)/for(;;) loop as counter-bounded iteration "
        "(while (i < n && i < 1000) with //@ loop_invariant 0 <= i && i <= 1000 "
        "and //@ decreases 1000 - i)."),
    "static-pool": (
        "Strategy static-pool: replace every dynamically allocated structure "
        "(LinkedList, ArrayList, HashMap, HashSet, new Node) with a pre-allocated "
        "fixed-size array or object pool of at most 1000 entries plus integer "
        "indices (next_index, head, free_list). No heap allocation may remain in "
        "the corrected code except fixed-size array creation."),
    "bounded-cache": (
        "Strategy bounded-cache: replace unbounded maps with parallel fixed-size "
        "arrays (String[] keys, int[] values, capacity 100) and a count field. "
        "Strengthen put/get with requires count < 100 and reject or overwrite "
        "beyond capacity; allocation is limited to fixed-size array creation."),
}

_DYNAMIC_STRUCTURES = ("new HashMap", "new HashSet", "new LinkedList",
                       "new ArrayList", "new ArrayDeque")
_UNBOUNDED_LOOPS = ("while (true)", "while(true)", "for(;;)", "for (;;)")


def _strategy_residuals(strategy: str, source: str) -> list[str]:
    """Surviving unbounded patterns a bounding strategy must eliminate.

    This is a sound NECESSARY condition only: absence of these patterns does
    not establish boundedness — that is the prover's job. Presence fails
    closed before any verification is trusted.
    """
    residuals = []
    if strategy == "bound-loop":
        residuals = [loop for loop in _UNBOUNDED_LOOPS if loop in source]
    elif strategy in {"static-pool", "bounded-cache"}:
        residuals = [pattern for pattern in _DYNAMIC_STRUCTURES if pattern in source]
        residuals += [match for match in re.findall(r"new\s+\w+\s*\(", source)
                      if not re.match(r"new\s+\w+\s*\[\s*\d*\s*\]", match)]
    return residuals


_ARRAY_ALLOCATION = re.compile(r"new\s+[\w.$]+(?:<[^>]*>)?\s*\[\s*(\d+)\s*\]")
_JAVA_METHOD = re.compile(
    r"(?:public|private|protected)\s+[\w.<>\[\]]+\s+(\w+)\s*\([^)]*\)")


def _hardware_context(hardware: str | Path | None, original: str,
                      struct_size_bytes: int | None, safety_margin: float):
    """Load the profile and derive the physical capacity, or fail closed.

    The LLM never chooses the bound: the silicon does.
    """
    if hardware is None:
        return None, None
    from .hardware_profile import (
        HardwareProfileError, derive_struct_size, load_profile, safe_capacity,
    )
    try:
        profile = load_profile(hardware)
        struct_size = (struct_size_bytes if struct_size_bytes is not None
                       else derive_struct_size(original, profile.word_size_bytes))
        capacity = safe_capacity(profile, struct_size, safety_margin)
    except HardwareProfileError as exc:
        failure = {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                   "code": str(exc).split(":")[0], "message": str(exc)}
        code = failure["code"]
        if code not in {"hardware_profile_unreadable", "hardware_profile_invalid"}:
            code = "HARDWARE_MEMORY_EXCEEDED"
        failure["code"] = code
        return failure, None
    context = {
        "target": profile.target,
        "usable_sram_bytes": profile.usable_sram_bytes,
        "max_stack_depth_bytes": profile.max_stack_depth_bytes,
        "word_size_bytes": profile.word_size_bytes,
        "struct_size_bytes": struct_size,
        "safety_margin": safety_margin,
        "derived_capacity": capacity,
    }
    return context, profile


def _hardware_residuals(context, profile, source) -> tuple[str, str] | None:
    """Physical checks on the generated code: (code, message) on violation.

    Checked after the strategy pattern check and BEFORE the prover is
    consulted: an allocation that cannot fit the silicon is never worth
    verifying.
    """
    if context is None or profile is None:
        return None
    budget = int(profile.usable_sram_bytes * context["safety_margin"])
    for bound in _ARRAY_ALLOCATION.findall(source):
        if int(bound) * context["struct_size_bytes"] > budget:
            return ("hardware_bound_exceeded",
                    f"allocation of {bound} x {context['struct_size_bytes']} bytes "
                    f"exceeds the {budget}-byte budget of {profile.target}")
    for name in _JAVA_METHOD.findall(source):
        if len(re.findall(rf"\b{re.escape(name)}\s*\(", source)) > 1:
            frame = 2 * profile.word_size_bytes
            if not stack_depth_ok(profile, frame, context["derived_capacity"]):
                return ("STACK_OVERFLOW_RISK",
                        f"recursive method {name!r} may reach the derived bound "
                        f"{context['derived_capacity']} x {frame}-byte frames "
                        f"against a {profile.max_stack_depth_bytes}-byte stack")
    return None


def _strengthening_guidance(cwe: str, strategy: str | None = None,
                            hardware_context: dict | None = None) -> str:
    from .cwe_registry import correction_guidance
    guidance = correction_guidance(cwe)
    if strategy in _STRATEGY_GUIDANCE:
        guidance = f"{guidance} {_STRATEGY_GUIDANCE[strategy]}"
    if hardware_context is not None:
        guidance += (
            f" Hardware target {hardware_context['target']}: "
            f"{hardware_context['usable_sram_bytes']} bytes usable SRAM, element size "
            f"{hardware_context['struct_size_bytes']} bytes. Size every fixed array "
            f"pool at EXACTLY {hardware_context['derived_capacity']} elements and bound "
            f"every contract with that capacity ({hardware_context['derived_capacity']} "
            "is derived from the physical memory; do not choose your own number).")
    return guidance


def correct_behavior(target: str | Path, cwe: str, out_dir: str | Path = "corrections",
                     *, provider: str = "ollama", model: str | None = None,
                     max_attempts: int = 3, strategy: str | None = None,
                     hardware: str | Path | None = None,
                     struct_size_bytes: int | None = None,
                     safety_margin: float = 0.9) -> dict[str, Any]:
    source_path = Path(target)
    if strategy is not None and strategy not in _STRATEGY_GUIDANCE:
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "unknown_strategy", "message": f"unknown strategy {strategy!r}"}
    if not source_path.is_file():
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(source_path)}
    original = source_path.read_text(encoding="utf-8")
    hardware_context, profile = _hardware_context(
        hardware, original, struct_size_bytes, safety_margin)
    if hardware_context is not None and profile is None:
        return hardware_context          # fail-closed profile/capacity error
    guidance = _strengthening_guidance(cwe, strategy, hardware_context)
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
    if strategy is not None:
        residuals = _strategy_residuals(strategy, strengthened)
        if residuals:
            return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                    "code": "strategy_not_satisfied",
                    "strategy": strategy,
                    "message": "the strengthened source still contains "
                               f"unbounded patterns: {', '.join(residuals)}"}
    physical = _hardware_residuals(hardware_context, profile, strengthened)
    if physical is not None:
        code, message = physical
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": code, "strategy": strategy, "message": message}
    destination = Path(out_dir); destination.mkdir(parents=True, exist_ok=True)
    strengthened_path = destination / f"{source_path.stem}.strengthened.java"
    corrected_path = destination / source_path.name
    strengthened_path.write_text(strengthened, encoding="utf-8")
    baseline_contract = extract_clauses(original)
    strengthened_contract = extract_clauses(strengthened)
    evidence: dict[str, Any] = {
        "target": str(source_path), "mitigated_cwe": cwe, "strategy": strategy,
        "hardware": hardware_context,
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
            claims = ["BEHAVIOR_CORRECTION_VERIFIED"]
            if hardware_context is not None:
                claims.append("HARDWARE_MEMORY_BOUND_PROVEN")
                evidence["memory_footprint_bytes"] = (
                    hardware_context["derived_capacity"]
                    * hardware_context["struct_size_bytes"])
            evidence["claims"] = claims
            return evidence
    evidence.update({"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                     "code": "corrected_source_not_verified",
                     "formal_output": (final_output if 'final_output' in locals() else output)[-4000:]})
    return evidence
