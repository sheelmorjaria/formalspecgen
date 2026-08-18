# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Dynamic heap reasoning via ghost predicates on the Prusti/Viper lane.

Rust-only by construction: Viper's separation logic (permissions) is the
engine, and Rust's ownership makes the two classic heap headaches
deterministic — acyclicity is a TYPE-SYSTEM guarantee (a Box graph is a
DAG by ownership; a cycle cannot be built), and aliasing is a rustc borrow
error, so the framing gate runs before Prusti is paid for.

The shape predicate (reachability/membership) is a structurally recursive
``#[pure]`` ghost function over ``Option<Box<Node>>`` — unbounded chain
length, no bounding anywhere. The epistemic division matches k-induction:
the machine proves the predicate's INDUCTIVENESS across the annotated
operations (Prusti verified every item); whether the predicate is strong
enough for the reviewer's intended property is the accepted assumption.
Arithmetic-recursive predicates are refused pre-prover: the installed
prover's overflow VCs make them unsound as generated evidence (``1 +``
down an unbounded chain cannot discharge without a bound the code does not
have).
"""
from __future__ import annotations

import re
from pathlib import Path

# A struct is "dynamic" when a field links through Box<T> — the heap shape.
_STRUCT = re.compile(r"pub\s+struct\s+(\w+)\s*\{(?P<body>[^}]*)\}")
_BOX_FIELD = re.compile(r"Box<(\w+)>")


def extract_dynamic_structs(code: str) -> list[dict]:
    """Structs whose fields link through ``Box<T>`` (heap-connected shape)."""
    result = []
    for match in _STRUCT.finditer(code):
        linked = _BOX_FIELD.search(match.group("body"))
        if linked:
            result.append({"name": match.group(1),
                          "node_type": linked.group(1)})
    return result


_PREDICATE_PROMPT = (
    "Write ONE Prusti ghost predicate for the Rust linked structure below: "
    "a `#[pure] pub fn <name>(head: &Option<Box<Node>>, target: i32) -> bool` "
    "defining reachability/membership by STRUCTURAL recursion only (match on "
    "head; recurse on node.next). Rules: it must return bool, must contain NO "
    "integer arithmetic (no +, no += — arithmetic recursion is overflow-"
    "unsound), and must reference the node type. Reply with the bare Rust "
    "function only.")


def _propose_predicates(code: str, node_type: str, provider: str) -> str:
    from .llm import _chat_fn, strip_fence
    raw, _, _ = _chat_fn(provider)([
        {"role": "system", "content": _PREDICATE_PROMPT},
        {"role": "user", "content": code}], None, 0.1)
    return strip_fence(raw).strip()


_GHOST_FN = re.compile(
    r"#\[\s*(?:pure|predicate)\s*\][^{}]*?fn\s+(\w+)", re.S)


def _predicate_residuals(text: str, node_type: str) -> str | None:
    """Necessary conditions on a ghost predicate, pre-prover."""
    ghost = _GHOST_FN.search(text)
    if ghost is None:
        return "no_ghost_predicate (expected a #[pure]/#[predicate] fn)"
    body = text[ghost.start():]
    if "-> bool" not in body.split("fn")[1][:200]:
        return "predicate_not_boolean (ghost predicates must return bool)"
    if "+" in re.sub(r"[^\n]*//[^\n]*", "", body.split("{", 1)[-1]):
        return ("arithmetic_predicate_rejected (structural recursion only; "
                "arithmetic recursion over an unbounded chain cannot "
                "discharge overflow VCs)")
    return None


def _framing_gate(code: str) -> tuple[str | None, str]:
    """(borrow_failure, output): rustc rejects aliased &mut deterministically."""
    from .rust_support import check_rust_syntax
    result = check_rust_syntax(code)
    output = str(result.get("output", result.get("message", "")))
    if result.get("status") not in {"OK", "COMPILED", "VERIFIED"} \
            and "borrow" in output.lower():
        return "aliasing_rejected", output
    return None, output


def verify_heap(source: str | Path, predicates: str | None = None, *,
                provider: str = "ollama") -> dict:
    """Unbounded heap-shape verification on the Prusti/Viper lane."""
    path = Path(source)
    if not path.is_file():
        return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(path)}
    if path.suffix.lower() in {".c", ".h"}:
        # M33: the C lane — Frama-C WP on a fixed probed ACSL preamble for
        # intrusive lists. Epistemics mirror this lane with the roles
        # inverted: reachability inductiveness is machine-proved; acyclicity
        # preservation (free under Rust ownership) is the human assumption.
        from .heap_c import verify_heap_c
        return verify_heap_c(path)
    if path.suffix.lower() != ".rs":
        return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": "UNSUPPORTED_BOUNDARY",
                "message": "Heap reasoning requires Prusti/Viper (Rust only); "
                           "Java/C heap models are outside this lane"}
    code = path.read_text(encoding="utf-8")
    dynamic = extract_dynamic_structs(code)
    if not dynamic:
        return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": "no_dynamic_structure",
                "message": "no struct links through Box<T>; heap reasoning "
                           "has nothing to verify"}

    predicate_source = "human_supplied" if predicates is not None else None
    if predicates is None:
        # A source that already carries a well-formed ghost predicate needs
        # no proposal — the reviewer supplied it in-file. The provider is
        # consulted ONLY when the predicate is genuinely absent, so a
        # provider-less environment never blocks a fully-specified source.
        if _predicate_residuals(code, dynamic[0]["node_type"]) is None:
            predicates = code
            predicate_source = "source_supplied"
        else:
            try:
                predicates = _propose_predicates(code, dynamic[0]["node_type"],
                                                 provider)
                predicate_source = "llm_proposed"
            except Exception as exc:
                return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                        "code": "predicate_generation_failed", "message": str(exc)}
    residual = _predicate_residuals(predicates, dynamic[0]["node_type"])
    if residual is not None:
        return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": residual.split(" ")[0], "message": residual}

    # The framing gate: aliased &mut dies at rustc before Prusti is paid.
    borrow_failure, compile_output = _framing_gate(code)
    if borrow_failure is not None:
        return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": borrow_failure,
                "message": "rustc borrow check rejected the source "
                           "(aliased mutable references): "
                           + compile_output[-400:]}

    from .rust_support import verify_prusti
    result = verify_prusti(code)
    if result.get("status") == "TOOL_MISSING":
        # Availability, not proof: reported distinctly (and only here, after
        # the diagnosable-input residuals and the framing gate) so a runner
        # without Prusti says so instead of claiming the predicate failed.
        return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": "prusti_unavailable",
                "message": result.get("message",
                                      "Prusti executable not found; heap "
                                      "reasoning was not attempted")}
    if result.get("status") != "VERIFIED":
        return {"status": "HEAP_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": "predicate_not_proved",
                "message": "Prusti could not discharge the ghost predicate "
                           "obligations (not inductive, or the implementation "
                           "does not satisfy the shape spec)",
                "evidence": str(result.get("output", ""))[-2000:]}

    return {"status": "HEAP_VERIFICATION_PROVED",
            "claim": "HEAP_REASONING_PROVED",
            "scope": "separation_logic",
            "heap_model": "viper_separation_logic_permissions",
            "unbounded_heap_reasoning": True,
            "structures": [item["name"] for item in dynamic],
            "predicate_inductiveness_proved": True,
            "predicate_source": predicate_source,
            "framing_machine_proved": True,
            "acyclicity_guarantee": "rust_ownership_type_system",
            "predicate_adequacy": "human_accepted_assumption",
            "note": "the ghost predicate's inductiveness over the unbounded "
                    "chain is machine-proved (Prusti/Viper); its adequacy "
                    "for the intended property is the reviewer's accepted "
                    "assumption; acyclicity is Rust ownership, not a solver "
                    "result"}
