"""Verified algorithm-optimization workflow with explicit non-equivalence boundaries."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .implementation import trusted_surface_matches
from .llm import _chat_fn, strip_fence
from .refactor_gate import verify_contract_preserving_refactor
from .verify import verify


_STRATEGIES = {"hashmap", "two_pointer", "binary_search", "nested_loop"}


def optimize_algorithm(source_path: str | Path, output_path: str | Path, *, strategy: str,
                       provider: str = "ollama", model: str | None = None) -> dict:
    source_file, destination = Path(source_path), Path(output_path)
    if strategy not in _STRATEGIES:
        return _fail("unsupported_strategy", f"strategy must be one of {sorted(_STRATEGIES)}")
    try:
        baseline = source_file.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("input_unavailable", str(exc))
    baseline_exit, baseline_output = verify(source_file, mode="esc")
    if baseline_exit != 0:
        return _fail("baseline_not_verified", baseline_output[-4000:])
    if strategy == "nested_loop":
        return _fail("complexity_regression_possible",
                     "nested_loop is not admitted as an optimization strategy")
    prompt = (f"Rewrite this verified Java/JML algorithm using the {strategy} strategy. "
              "Preserve every class, field, method signature, import, and JML clause exactly. "
              "Return only one complete ```java fenced file. Do not claim complexity or proof.\n\n" + baseline)
    try:
        raw, used_model, usage = _chat_fn(provider)([
            {"role": "system", "content": "You are a formally verified algorithm engineer."},
            {"role": "user", "content": prompt}], model, 0.2)
        candidate = strip_fence(raw)
    except Exception as exc:
        return _fail("optimization_generation_failed", str(exc))
    trusted, differences = trusted_surface_matches(baseline, candidate)
    if not trusted:
        return _fail("trusted_surface_changed", differences)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(candidate, encoding="utf-8")
    candidate_exit, candidate_output = verify(destination, mode="esc")
    if candidate_exit != 0:
        return _fail("optimized_candidate_not_verified", candidate_output[-4000:])
    gate = verify_contract_preserving_refactor(source_file, destination)
    if gate.get("status") != "VERIFIED":
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "refactor_gate_failed",
                "verification": gate, "behavior_equivalence_proved": False}
    return {"status": "VERIFIED", "claim": "ALGORITHM_OPTIMIZATION_VERIFIED",
            "strategy": strategy, "model": used_model, "usage": usage,
            "baseline_sha256": hashlib.sha256(baseline.encode()).hexdigest(),
            "optimized_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
            "baseline_verification": {"exit_code": baseline_exit},
            "optimized_verification": {"exit_code": candidate_exit},
            "verification": gate, "behavior_equivalence_proved": False,
            "complexity_improvement_proved": False,
            "disclaimer": "The shared contract is preserved; runtime bisimulation and complexity are not proved."}


def _fail(code: str, message) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "behavior_equivalence_proved": False}
