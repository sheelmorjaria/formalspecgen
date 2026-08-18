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
        "the corrected code except fixed-size array creation. When the pool is "
        "full, either return an explicit failure value or throw a dedicated "
        "CapacityReachedException ONLY under a capacity guard, with a JML "
        "signals clause pinning the throw to the boundary "
        "(signals (CapacityReachedException e) acquired == capacity)."),
    "bounded-cache": (
        "Strategy bounded-cache: replace unbounded maps with parallel fixed-size "
        "arrays (String[] keys, int[] values, capacity 100) and a count field. "
        "Strengthen put/get with requires count < 100 and reject or overwrite "
        "beyond capacity; allocation is limited to fixed-size array creation."),
    "bounded-pool": (
        "Strategy bounded-pool: replace every dynamic collection with a bounded "
        "object pool BoundedPool<T> holding a fixed capacity, an acquired count, "
        "and acquire(T)/release(T) operations. map list.add(x) to "
        "pool.acquire(x) returning false when the pool is full and "
        "list.remove(x) to pool.release(x). Strengthen the contract with "
        "requires capacity > 0 && capacity <= CAP and ensures count <= CAP, and "
        "give acquire the explicit reject-when-full postcondition "
        "\\result == (old count < CAP). Objects may be allocated on demand; the "
        "BOUND is what must be fixed. The rejection may equally be a dedicated "
        "CapacityReachedException thrown ONLY under the capacity guard, with the "
        "signals postcondition signals (CapacityReachedException e) "
        "acquired == capacity pinning the throw to the boundary; whether the "
        "caller then applies backpressure, enters a fail-safe mode, or spills "
        "to a queue is a deployment decision outside this correction."),
    # Hardening strategies: each targets its own weakness class rather than
    # capacity. Same rule as the bounding set — the residual check is a
    # NECESSARY condition only; the prover still judges the contract.
    "checked-math": (
        "Strategy checked-math: rewrite every unguarded arithmetic operation on "
        "int-typed values as overflow-checked arithmetic — Math.addExact, "
        "Math.subtractExact, Math.multiplyExact, or an explicit pre-test "
        "against Integer.MAX_VALUE/Integer.MIN_VALUE — and strengthen the "
        "contract with the range that forbids wrapping (requires total >= 0 "
        "&& total <= Integer.MAX_VALUE - n, ensures the result stays in range "
        "or a failure value is returned)."),
    "lock-timeout": (
        "Strategy lock-timeout: replace every synchronized method/block and "
        "every bare lock() with ReentrantLock.tryLock(timeout, TimeUnit). On "
        "timeout, return an explicit failure value (do NOT block or spin), and "
        "always release in finally { lock.unlock(); }. Strengthen the contract "
        "with the failure postcondition ensures \\result == failureValue on the "
        "timeout path."),
    "canonicalize": (
        "Strategy canonicalize: never concatenate an untrusted value into "
        "output. Encode every untrusted string before it reaches a response or "
        "markup — org.owasp.encoder.Encode.forHtml (or an equivalent escape "
        "helper) around each interpolated parameter — and strengthen the "
        "contract so the returned markup contains only escaped parameter text."),
    "fail-safe": (
        "Strategy fail-safe: remove every assert statement — a reachable "
        "assertion is a crash under attacker control. Replace each with "
        "explicit validation that returns a failure value or throws a checked, "
        "documented exception, and mirror that behavior in the contract "
        "(ensures \\result == failureValue when the precondition on the value "
        "does not hold)."),
    "immutable-snapshot": (
        "Strategy immutable-snapshot: stop sharing mutable state. Make shared "
        "fields private and publish immutable snapshots — construct with "
        "List.copyOf/Arrays.copyOf, return Collections.unmodifiable views or "
        "fresh copies from accessors — so no caller can mutate another "
        "thread's view. Strengthen the contract with ensures that returned "
        "references cannot alias internal mutable state."),
}

_DYNAMIC_STRUCTURES = ("new HashMap", "new HashSet", "new LinkedList",
                       "new ArrayList", "new ArrayDeque")
_UNBOUNDED_LOOPS = ("while (true)", "while(true)", "for(;;)", "for (;;)")


_POOL_WITHOUT_CAPACITY = re.compile(
    r"new\s+(?:[\w.$]+\.)*BoundedPool\s*(?:<[^>]*>)?\s*\(\s*\)")
_CAPACITY_ARGUED = re.compile(r"<=?\s*capacity\b|\bcapacity\s*[<>=]")
_COLLECTION_API = re.compile(r"\.\s*(?:add|remove)\s*\(")
# M17: reject-by-exception is a legitimate boundary behavior, but the throw
# must live under a capacity-arguing guard (the signals clause then pins it
# to the boundary; Z3 judges the exceptional paths).
_THROW = re.compile(r"throw\s+new\s+\w*(?:Exception|Error)")
_CAPACITY_GUARDED_THROW = re.compile(
    r"if\s*\([^)]*\b(?:capacity|acquired|count|size|next_index)\b[^)]*\)\s*"
    r"\{[^{}]*?throw\s+new", re.S)

# Hardening-strategy shape evidence. Each residual set is a NECESSARY
# condition: the rewrite must carry its strategy's idiom and must not keep
# the vulnerable shape it was asked to remove.
_OVERFLOW_CHECKED = re.compile(
    r"Math\s*\.\s*(?:add|subtract|multiply)Exact\s*\(|"
    r"Integer\s*\.\s*(?:MAX|MIN)_VALUE")
_BARE_LOCK = re.compile(r"\.\s*lock\s*\(\s*\)")
_FINALLY_UNLOCK = re.compile(r"finally\s*\{[^}]*unlock\s*\(", re.S)
_ENCODING = re.compile(r"Encode\s*\.\s*for\w+|escape\w*\s*\(|encode\w*\s*\(")
_REACHABLE_ASSERT = re.compile(r"(?m)^\s*assert\b")
_SNAPSHOT_IDIOM = re.compile(
    r"List\s*\.\s*copyOf\s*\(|Arrays\s*\.\s*copyOf\s*\(|"
    r"Collections\s*\.\s*unmodifiable\w+|Map\s*\.\s*copyOf\s*\(")
_PUBLIC_MUTABLE_FIELD = re.compile(
    r"public\s+(?!final\b|static\s+final\b)[\w.<>\[\], ]*?"
    r"(?:\[\]|List|Map|Set)(?:<[^>]*>)?\s+\w+\s*[;=]")


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
        if _THROW.search(source) and not _CAPACITY_GUARDED_THROW.search(source):
            residuals.append("unguarded capacity throw (a reject-by-exception "
                             "rewrite must throw only under a capacity guard, "
                             "with a signals clause pinning the throw to the "
                             "boundary)")
    elif strategy == "bounded-pool":
        # On-demand allocation is the POINT of a pool, so non-array `new` is
        # allowed — but the collection must be gone, the collection API must
        # be remapped to acquire/release, and a rewrite that never argues an
        # explicit capacity is an unbounded pool and fails closed.
        residuals = [pattern for pattern in _DYNAMIC_STRUCTURES if pattern in source]
        residuals += [match + ")" for match in
                      _POOL_WITHOUT_CAPACITY.findall(source)]
        residuals += [f"{match}) collection API must map to pool.acquire/release"
                      for match in _COLLECTION_API.findall(source)]
        if not _CAPACITY_ARGUED.search(source):
            residuals.append("no explicit capacity bound (a bounded-pool "
                             "rewrite must argue a capacity: requires/"
                             "ensures count <= capacity or a < capacity guard)")
        if _THROW.search(source) and not _CAPACITY_GUARDED_THROW.search(source):
            residuals.append("unguarded capacity throw (a reject-by-exception "
                             "rewrite must throw only under a capacity guard, "
                             "with a signals clause pinning the throw to the "
                             "boundary)")
    elif strategy == "checked-math":
        if not _OVERFLOW_CHECKED.search(source):
            residuals.append("no checked arithmetic (a checked-math rewrite "
                             "must use Math.addExact/subtractExact/"
                             "multiplyExact or an explicit Integer.MAX_VALUE/"
                             "MIN_VALUE bound)")
    elif strategy == "lock-timeout":
        if "synchronized" in source:
            residuals.append("synchronized still present (lock-timeout "
                             "replaces blocking locks with tryLock)")
        residuals += [f"{match}) bare lock() must become tryLock(timeout)"
                      for match in _BARE_LOCK.findall(source)]
        if "tryLock" not in source:
            residuals.append("no tryLock (a lock-timeout rewrite must bound "
                             "the wait with tryLock(timeout, TimeUnit))")
        if not _FINALLY_UNLOCK.search(source):
            residuals.append("no finally { unlock(); } (every acquired lock "
                             "must be released on all paths)")
    elif strategy == "canonicalize":
        if not _ENCODING.search(source):
            residuals.append("no output encoding (a canonicalize rewrite "
                             "must encode untrusted values with "
                             "Encode.forHtml or an equivalent escape helper "
                             "before they reach output)")
    elif strategy == "fail-safe":
        residuals += [f"{match.strip()} removed-check still reachable"
                      for match in _REACHABLE_ASSERT.findall(source)]
    elif strategy == "immutable-snapshot":
        if not _SNAPSHOT_IDIOM.search(source):
            residuals.append("no snapshot idiom (an immutable-snapshot "
                             "rewrite must publish copies with List.copyOf/"
                             "Arrays.copyOf/Collections.unmodifiable)")
        residuals += [f"{match.strip()} mutable shared field must be private "
                      "final or replaced by a snapshot"
                      for match in _PUBLIC_MUTABLE_FIELD.findall(source)]
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


def _hw_invariant_ast(name: str, lo: int, hi: int) -> dict:
    """`lo <= name && name <= hi` in the strict V2 expression schema."""
    return {"kind": "and",
            "left": {"kind": "gte", "left": {"kind": "field", "name": name},
                     "right": {"kind": "integer", "value": lo}},
            "right": {"kind": "lte", "left": {"kind": "field", "name": name},
                      "right": {"kind": "integer", "value": hi}}}


def _correct_v2_candidate(target: str | Path, cwe: str, out_dir: str | Path,
                          strategy: str | None, hardware: str | Path | None,
                          struct_size_bytes: int | None,
                          safety_margin: float) -> dict[str, Any]:
    """Deterministic capacity bounding of a V2 candidate: the C/Rust lane.

    No LLM: the silicon chooses the number. Int state-variable bounds are
    clamped to the hardware-derived capacity (unbounded fields GAIN a bound),
    hardware invariants are added, and a NEW `<module>_bounded.v2.yaml` is
    written beside the original. Proof stays downstream — validate-domain
    (TLC), hash-bound promotion, then Prusti on the deterministic Rust
    lowering — so this command mints an APPLIED claim, never a PROVEN one.
    """
    candidate_path = Path(target)
    if not candidate_path.is_file():
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(candidate_path)}
    if cwe != "CWE-400":
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "unsupported_cwe_for_candidate",
                "message": "V2 candidate correction currently supports only "
                           "CWE-400 capacity bounding"}
    if strategy not in {"static-pool", "bounded-cache", "bounded-pool"}:
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "strategy_not_applicable",
                "message": "state-machine candidates accept static-pool or "
                           "bounded-cache (loop rewrites are a source-level "
                           "correction, not a math-level one)"}
    if hardware is None:
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "hardware_profile_required",
                "message": "candidate bounding derives the capacity from a "
                           "hardware profile; pass --hardware PROFILE.json"}
    from .hardware_profile import HardwareProfileError, load_profile, safe_capacity
    import yaml as _yaml
    try:
        spec = _yaml.safe_load(candidate_path.read_text(encoding="utf-8"))
        int_vars = [v for v in spec.get("state_variables", [])
                    if v.get("kind") == "int"]
        struct_size = (struct_size_bytes if struct_size_bytes is not None
                       else len(int_vars) * load_profile(hardware).word_size_bytes)
        profile = load_profile(hardware)
        capacity = safe_capacity(profile, struct_size, safety_margin)
    except HardwareProfileError as exc:
        failure = {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                   "code": str(exc).split(":")[0], "message": str(exc)}
        code = failure["code"]
        if code not in {"hardware_profile_unreadable", "hardware_profile_invalid"}:
            code = "HARDWARE_MEMORY_EXCEEDED"
        failure["code"] = code
        return failure
    except (OSError, ValueError, _yaml.YAMLError) as exc:
        return {"status": "CORRECTION_FAILED", "claim": "NO_PROOF",
                "code": "candidate_unreadable", "message": str(exc)}

    module = spec["module_name"]
    bounded = dict(spec)
    bounded["module_name"] = f"{module}_bounded"
    bounded["domain_name"] = "".join(
        part[:1].upper() + part[1:]
        for part in bounded["module_name"].split("_") if part)
    bounded["state_variables"] = []
    clamped, gained = [], []
    for var in spec.get("state_variables", []):
        var = dict(var)
        if var.get("kind") == "int":
            bound = var.get("bound")
            if bound is None:
                var["bound"] = [0, capacity]
                gained.append(var["name"])
            elif bound[1] > capacity:
                var["bound"] = [bound[0], capacity]
                clamped.append(var["name"])
        bounded["state_variables"].append(var)
    # Growth guards: a machine clamped to C whose growth op still fires at
    # C would produce C+1 and fail the traverser (out of bounds) — the
    # guard is semantically required, not documentation. Every +n effect on
    # a bounded field gains `field < hi` so growth stops exactly at the
    # capacity and push rejects when full.
    bounded["operations"] = []
    clamped_or_gained = set(clamped) | set(gained)
    bounds_by_name = {v["name"]: v["bound"] for v in bounded["state_variables"]
                      if v.get("kind") == "int"}
    for op in spec.get("operations", []):
        op = dict(op)
        guards = list(op.get("guards", []))
        for effect in op.get("effects", []):
            value = effect.get("value", {})
            if (value.get("kind") == "add"
                    and isinstance(value.get("right"), dict)
                    and value["right"].get("kind") == "integer"
                    and value["right"].get("value", 0) > 0
                    and effect.get("target") in clamped_or_gained):
                field = effect["target"]
                growth = {"id": f"g_hw_growth_{op['name']}_{field}",
                          "expression": {"kind": "lt",
                                         "left": {"kind": "field", "name": field},
                                         "right": {"kind": "integer",
                                                   "value": bounds_by_name[field][1]}}}
                if growth["expression"] not in [g.get("expression")
                                                for g in guards]:
                    guards.append(growth)
        op["guards"] = guards
        bounded["operations"].append(op)
    bounded["capacity_bound"] = capacity
    bounded["struct_size_bytes"] = struct_size
    bounded["tlc_invariants"] = list(spec.get("tlc_invariants", [])) + [
        {"id": f"inv_hw_bound_{v['name']}",
         "expression": _hw_invariant_ast(v["name"], v["bound"][0], v["bound"][1])}
        for v in bounded["state_variables"] if v.get("kind") == "int"]

    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    bounded_path = destination / f"{module}_bounded.v2.yaml"
    bounded_path.write_text(
        _yaml.safe_dump(bounded, sort_keys=False, allow_unicode=True),
        encoding="utf-8")
    context = {"target": profile.target,
               "usable_sram_bytes": profile.usable_sram_bytes,
               "max_stack_depth_bytes": profile.max_stack_depth_bytes,
               "word_size_bytes": profile.word_size_bytes,
               "struct_size_bytes": struct_size,
               "safety_margin": safety_margin,
               "derived_capacity": capacity}
    return {"status": "CAPACITY_BOUND_CANDIDATE_GENERATED", "claim": "NO_PROOF",
            "claims": ["CAPACITY_BOUNDING_APPLIED"],
            "mitigated_cwe": cwe, "strategy": strategy,
            "target": str(candidate_path),
            "bounded_candidate": str(bounded_path),
            "hardware": context,
            "derived_capacity": capacity,
            "struct_size_bytes": struct_size,
            "clamped_fields": clamped, "gained_bounds": gained,
            "memory_footprint_bytes": capacity * struct_size,
            "next_steps": [
                "validate-domain parser_bounded --project-root <root>",
                "promote-domain parser_bounded --accept-candidate-sha256 <hash>",
                "draft \"...\" --canonical-domain parser_bounded --lang rust",
            ]}


def correct_behavior(target: str | Path, cwe: str, out_dir: str | Path = "corrections",
                     *, provider: str = "ollama", model: str | None = None,
                     max_attempts: int = 3, strategy: str | None = None,
                     hardware: str | Path | None = None,
                     struct_size_bytes: int | None = None,
                     safety_margin: float = 0.9,
                     auto_strategy: bool = False) -> dict[str, Any]:
    source_path = Path(target)
    if auto_strategy and source_path.suffix.lower() not in {".yaml", ".yml"}:
        from .correction_router import auto_route_correction
        return auto_route_correction(source_path, cwe, out_dir,
                                     hardware=hardware,
                                     struct_size_bytes=struct_size_bytes,
                                     provider=provider, model=model,
                                     max_attempts=max_attempts)
    if source_path.suffix.lower() in {".yaml", ".yml"}:
        return _correct_v2_candidate(source_path, cwe, out_dir, strategy,
                                     hardware, struct_size_bytes, safety_margin)
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
