"""Deterministic strategy routing: the code's own shape picks the correction.

No LLM and no heuristics-beyond-text are involved in the CHOICE — routing is
a pure function of (source text, CWE, optional hardware profile). Each CWE
owns its own shape table, so a shape from one weakness class never routes a
strategy from another. An unrecognized shape returns None so callers fail
closed to manual review; routing never weakens the downstream gates (the
strategy residual check and the prover still judge the rewrite exactly as an
explicit --strategy would).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Ordered by precedence: an unbounded loop is the more acute resource bug
# and its correction is orthogonal to (and composable with, in the source)
# whatever collection also lives in the file.
_MAP_STRUCTURES = ("new HashMap", "new HashSet", "new TreeMap",
                   "new LinkedHashMap", "new ConcurrentHashMap")
_LIST_STRUCTURES = ("new LinkedList", "new ArrayList", "new ArrayDeque",
                    "new PriorityQueue", "new Stack")
_UNBOUNDED_LOOPS = ("while (true)", "while(true)", "for(;;)", "for (;;)")
_LOOP_GUARD = re.compile(
    r"while\s*\(\s*true\s*\)|while\s*\(\s*1\s*\)|for\s*\(\s*;\s*;\s*\)")
_COLLECTION_API = re.compile(r"\.\s*(?:add|put|offer|push)\s*\(")

# Below this derived capacity a pool's on-demand-allocation advantage is
# noise; the eager static array is the simpler, safer target.
_TINY_POOL_CAPACITY = 16

# CWE-scoped shape tables (M16). Routing is and stays a pure function of
# (source text, CWE): each weakness class has its own matrix, and a shape
# from one class NEVER routes a strategy from another — the capacity matrix
# is not the overflow matrix.
_INT_ARITHMETIC = re.compile(r"\w+\s*(?:\+=|\*=)\s*\w|\w\s*\*\s*\w")
_UNSAFE_LOCK = re.compile(r"\bsynchronized\b|\.\s*lock\s*\(\s*\)")
# Either an output-sink call with concatenation inside, or markup being
# built by concatenation at all (the raw `"<h1>" + name` shape).
_XSS_SINK = re.compile(
    r'"<[^"]*"\s*\+|\+\s*"[^"]*<|'
    r"(?:print|write|append|println|format)\s*\([^)]*\+|getWriter\s*\(")
_REACHABLE_ASSERT = re.compile(r"(?m)^\s*assert\b")
_SHARED_MUTABLE_FIELD = re.compile(
    r"(?:public|protected|static)\s+(?!final\b|static\s+final\b)"
    r"[\w.<>\[\], ]*?(?:\[\]|List|Map|Set)(?:<[^>]*>)?\s+\w+\s*[;=]")


def _route_cwe400(source_text: str) -> str | None:
    """Precedence: unbounded loop > dynamic map > dynamic list/deque. A shape
    with a collection constructor but no mutating call is still routable
    (the constructor alone is the unbounded commitment); a clean source
    returns None for manual review.
    """
    if _LOOP_GUARD.search(source_text) or any(
            loop in source_text for loop in _UNBOUNDED_LOOPS):
        return "bound-loop"
    if any(structure in source_text for structure in _MAP_STRUCTURES):
        return "bounded-cache"
    if any(structure in source_text for structure in _LIST_STRUCTURES):
        return "bounded-pool"
    # A collection used without its constructor visible in this unit (e.g.
    # injected via constructor) still exhibits the unbounded API.
    if _COLLECTION_API.search(source_text):
        return "bounded-pool"
    return None


_CWE_SHAPE_TABLES = {
    "CWE-400": _route_cwe400,
    "CWE-190": lambda text: (
        "checked-math" if re.search(r"\bint\b", text)
        and _INT_ARITHMETIC.search(text) else None),
    "CWE-667": lambda text: (
        "lock-timeout" if _UNSAFE_LOCK.search(text) else None),
    "CWE-79": lambda text: (
        "canonicalize" if _XSS_SINK.search(text) else None),
    "CWE-617": lambda text: (
        "fail-safe" if _REACHABLE_ASSERT.search(text) else None),
    "CWE-362": lambda text: (
        "immutable-snapshot" if _SHARED_MUTABLE_FIELD.search(text) else None),
}


def route_strategy(source_text: str, cwe: str = "CWE-400") -> str | None:
    """Map the source's shape to a correction strategy, or None.

    Routing is CWE-scoped: only the table for the weakness being corrected
    is consulted, so an unbounded loop under a CWE-190 request cannot be
    mis-routed to bound-loop. An unrecognized CWE fails closed to None
    (manual review) just like an unrecognized shape.
    """
    table = _CWE_SHAPE_TABLES.get(cwe)
    return table(source_text) if table is not None else None


def _resolve_profile(hardware_profile: dict | Path):
    """Accept a profile file path or an already-loaded dict."""
    from .hardware_profile import Profile
    if isinstance(hardware_profile, dict):
        return Profile(**hardware_profile)
    from .hardware_profile import load_profile
    return load_profile(hardware_profile)


def select_strategy(source_text: str, hardware_profile: dict | Path | None,
                    struct_size_bytes: int | None = None,
                    cwe: str = "CWE-400") -> str | None:
    """route_strategy with hardware awareness: on a tiny profile the
    bounded-pool vs static-pool distinction collapses to static-pool. The
    collapse is a CAPACITY concern, so it applies only on the CWE-400 table."""
    strategy = route_strategy(source_text, cwe)
    if strategy != "bounded-pool" or hardware_profile is None:
        return strategy
    profile = _resolve_profile(hardware_profile)
    size = struct_size_bytes
    if size is None:
        from .hardware_profile import derive_struct_size
        size = derive_struct_size(source_text, profile.word_size_bytes)
    from .hardware_profile import safe_capacity
    if safe_capacity(profile, size) < _TINY_POOL_CAPACITY:
        return "static-pool"
    return "bounded-pool"


def auto_route_correction(target: str | Path, cwe: str,
                          out_dir: str | Path = "corrections", *,
                          hardware: str | Path | None = None,
                          struct_size_bytes: int | None = None,
                          **lane_kwargs: Any) -> dict[str, Any]:
    """Route on shape, then run the normal correction lane.

    The verdict records strategy_routed=True so reviewers can distinguish a
    router-chosen strategy from an explicit human one; everything downstream
    (strategy residuals, hardware residuals, ESC) is the shared lane.
    """
    source_path = Path(target)
    if not source_path.is_file():
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(source_path)}
    source_text = source_path.read_text(encoding="utf-8")
    strategy = select_strategy(source_text, hardware, struct_size_bytes, cwe=cwe)
    if strategy is None:
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "no_routable_strategy",
                "message": "no correction strategy matches this code's "
                           "shape; manual review required"}
    from .behavior_correction import correct_behavior
    result = correct_behavior(source_path, cwe, out_dir, strategy=strategy,
                              hardware=hardware,
                              struct_size_bytes=struct_size_bytes,
                              **lane_kwargs)
    if result.get("status") != "CORRECTION_FAILED" or result.get(
            "code") != "input_unavailable":
        result["strategy_routed"] = True
    return result
