# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M46: kernel composition — the orchestrator's precondition flow.

The blueprint's Phase 5 semantics as a deterministic gate: the kernel's
boot sequence is an ordered list of steps; each step DECLARES what it
establishes (postconditions) and what it requires (preconditions). The
gate proves the flow is satisfiable — every requirement is established
by an earlier step (a step's own establishes satisfy its requires only
if that step runs after them: self-establishment is refused), and the
dependency graph is acyclic.

Honest scope: this is deterministic precondition-flow arithmetic over
declared facts, the same epistemic class as M39's range disjointness —
NOT the OpenJML contract-composition lane (``compose``), which proves
reviewed V2 domain contracts and remains the tool for that lifecycle.
The claim minted here is SYSTEM_COMPOSITION_PROVED, scope
``deterministic_precondition_flow``; the orchestrator's Rust glue is
NOT proven by this gate.
"""
from __future__ import annotations


def _refuse(code: str, message: str) -> dict:
    return {"status": "COMPOSITION_VERIFICATION_FAILED", "claim":
            "NO_PROOF", "code": code, "message": message}


def verify_composition(artifact: dict) -> dict:
    """Prove the boot sequence establishes every callee precondition."""
    if not isinstance(artifact, dict):
        return _refuse("composition_artifact_invalid",
                       "the composition artifact must be an object")
    steps = artifact.get("steps")
    if not isinstance(steps, list) or not steps:
        return _refuse("steps_missing",
                       "composition declares no steps — the boot "
                       "sequence is a human declaration, never guessed")

    established: dict[str, str] = {}   # fact -> step that established it
    requirements: list[tuple[str, str]] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or "name" not in step:
            return _refuse("step_field_missing",
                           f"step {index} lacks a name")
        name = str(step["name"])
        requires = step.get("requires", [])
        establishes = step.get("establishes", [])
        if not isinstance(requires, list) or not isinstance(establishes, list):
            return _refuse("step_field_missing",
                           f"step {name!r}: requires/establishes must be "
                           "lists of declared facts")
        for fact in requires:
            requirements.append((name, str(fact)))
            if fact not in established:
                return _refuse(
                    "COMPOSITION_PRECONDITION_UNMET",
                    f"step {name!r} requires {fact!r} but no earlier "
                    "step establishes it — the boot order is refused")
            if established[fact] == name:
                return _refuse(
                    "COMPOSITION_PRECONDITION_UNMET",
                    f"step {name!r} requires {fact!r} which it claims to "
                    "establish itself — self-establishment is refused")
        for fact in establishes:
            established[str(fact)] = name
    # cycles are impossible in a linear boot order (a later step can
    # never establish a fact an earlier step needed) — but a step that
    # establishes a fact ALREADY established re-treads ground; that is
    # a redundant, conflicting declaration and is refused by name
    seen: dict[str, str] = {}
    for step in steps:
        for fact in step.get("establishes", []):
            fact = str(fact)
            if fact in seen:
                return _refuse("COMPOSITION_FACT_REESTABLISHED",
                               f"fact {fact!r} established by both "
                               f"{seen[fact]!r} and {step['name']!r}")
            seen[fact] = str(step["name"])
    return {
        "status": "SYSTEM_COMPOSITION_PROVED",
        "claim": "SYSTEM_COMPOSITION_PROVED",
        "scope": "deterministic_precondition_flow",
        "judge": "deterministic_gate",
        "steps": [str(step["name"]) for step in steps],
        "facts_established": sorted(seen),
        "preconditions_checked": len(requirements),
        "note": "boot-order precondition flow is decidable arithmetic; "
                "contract-level composition of reviewed V2 domains is "
                "the separate compose lane (OpenJML ESC)",
    }
