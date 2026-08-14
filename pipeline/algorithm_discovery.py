"""Experimental strategy fan-out for discovering contract-proven algorithms."""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .implementation import trusted_surface_matches
from .llm import _chat_fn, strip_fence
from .refactor_gate import verify_contract_preserving_refactor
from .verify import verify


STRATEGY_REGISTRY: dict[str, dict[str, str]] = {
    "brute_force": {"instruction": "Use a straightforward exhaustive loop; clarity is preferred.",
                    "complexity": "O(n^2)"},
    "two_pointer": {"instruction": "Use an O(n) two-pointer approach with explicit loop invariants. "
                    "OpenJML 21 rule: never use loop_assignable; use only loop_invariant and decreases.",
                    "complexity": "O(n)"},
    "hashmap": {"instruction": "Use an O(n) array-backed map; do not use opaque collection semantics.",
                 "complexity": "O(n)"},
    "sliding_window": {"instruction": "Use an O(n) sliding window with expanding and contracting pointers.",
                       "complexity": "O(n)"},
    "binary_search": {"instruction": "Use an O(log n) binary search with bounded pointer invariants.",
                       "complexity": "O(log n)"},
    "prefix_sum": {"instruction": "Use an O(n) prefix-sum array; prove each cumulative assignment with loop invariants.",
                   "complexity": "O(n)"},
    "bit_manipulation": {"instruction": "Use O(1) space and bitwise operators such as XOR; avoid opaque collections.",
                         "complexity": "O(n)"},
    "dynamic_programming": {"instruction": "Use O(n) iterative tabulation with explicit recurrence loop invariants; do not recurse.",
                            "complexity": "O(n)"},
}


def _rank(complexity: str) -> int:
    return {"O(log n)": 3, "O(n)": 2, "O(n^2)": 1}.get(complexity, 0)


def _candidate(source: Path, destination: Path, strategy: str, provider: str,
               model: str | None) -> dict[str, Any]:
    baseline = source.read_text(encoding="utf-8")
    instruction = STRATEGY_REGISTRY[strategy]["instruction"]
    prompt = (f"Rewrite this verified Java/JML source using this strategy: {instruction} "
              "Preserve the class, public API, imports, and every public JML clause exactly. "
              "Include strategy-specific loop invariants. Return only one complete Java file.\n\n"
              + baseline)
    try:
        raw, used_model, usage = _chat_fn(provider)([
            {"role": "system", "content": "You are a formally verified algorithm engineer."},
            {"role": "user", "content": prompt}], model, 0.2)
        candidate = strip_fence(raw)
    except Exception as exc:
        return {"strategy": strategy, "status": "FAIL", "code": "generation_failed",
                "message": str(exc), "complexity": STRATEGY_REGISTRY[strategy]["complexity"]}
    trusted, differences = trusted_surface_matches(baseline, candidate)
    if not trusted:
        return {"strategy": strategy, "status": "FAIL", "code": "trusted_surface_changed",
                "message": differences, "complexity": STRATEGY_REGISTRY[strategy]["complexity"]}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(candidate, encoding="utf-8")
    exit_code, output = verify(destination, mode="esc")
    if exit_code != 0:
        return {"strategy": strategy, "status": "FAIL", "code": "candidate_not_verified",
                "message": output[-4000:], "file": str(destination),
                "complexity": STRATEGY_REGISTRY[strategy]["complexity"]}
    gate = verify_contract_preserving_refactor(source, destination)
    if gate.get("status") != "VERIFIED":
        return {"strategy": strategy, "status": "FAIL", "code": "refactor_gate_failed",
                "verification": gate, "file": str(destination),
                "complexity": STRATEGY_REGISTRY[strategy]["complexity"]}
    return {"strategy": strategy, "status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
            "file": str(destination), "complexity": STRATEGY_REGISTRY[strategy]["complexity"],
            "model": used_model, "usage": usage,
            "source_sha256": hashlib.sha256(baseline.encode()).hexdigest(),
            "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
            "verification": gate, "behavior_equivalence_proved": False}


def discover_algorithms(source_path: str | Path, out_dir: str | Path = "discovered",
                        strategies: list[str] | None = None, provider: str = "ollama",
                        model: str | None = None, max_workers: int = 3) -> dict[str, Any]:
    source = Path(source_path)
    destination = Path(out_dir)
    selected = list(STRATEGY_REGISTRY) if strategies is None else strategies
    unknown = [item for item in selected if item not in STRATEGY_REGISTRY]
    if unknown:
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "unsupported_strategy",
                "message": f"unknown strategies: {unknown}", "verified_candidates": []}
    if not source.is_file():
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "input_unavailable",
                "message": str(source), "verified_candidates": []}
    results: list[dict[str, Any]] = []
    workers = max(1, min(max_workers, len(selected) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_candidate, source, destination / name / f"{source.stem}.java",
                               name, provider, model): name for name in selected}
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: (item["status"] != "VERIFIED", -_rank(item.get("complexity", "")),
                                   item["strategy"]))
    verified = [item for item in results if item["status"] == "VERIFIED"]
    return {"status": "VERIFIED" if verified else "FAIL",
            "claim": "ALGORITHM_DISCOVERY_COMPLETE" if verified else "NO_PROOF",
            "source": str(source), "strategies": selected,
            "verified_candidates": verified,
            "failed_strategies": [item["strategy"] for item in results if item["status"] != "VERIFIED"],
            "results": results, "behavior_equivalence_proved": False,
            "complexity_improvement_proved": False}
