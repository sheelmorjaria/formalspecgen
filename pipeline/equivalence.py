# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded behavioral bisimulation between two V2 state machines.

Given two V2 domains and a reviewer-supplied state mapping, the checker
enumerates both machines' FINITE reachable state spaces (bounded by the
variables' declared bounds, capped like the traverser) and verifies the
mapping is a bisimulation: for every related pair, every successor on one
side has a related counterpart on the other, in both directions. Exhaustive
over the reachable spaces, this is a complete proof for the bounded
abstractions — not an induction, and not a claim about Java heap behavior.
"""
from __future__ import annotations

import json
from collections import deque
from pathlib import Path

from .domain_v2_promotion import ReviewedDomainSpecV2, load_candidate
from .domain_v2_model import (
    MAX_STATE_SPACE, apply_effects, guards_hold, state_space_upper_bound,
)

def _load_domain(path: str | Path):
    try:
        return load_candidate(path)
    except Exception:
        return ReviewedDomainSpecV2.model_validate(
            json.loads(Path(path).read_text(encoding="utf-8")))


def load_state_mapping(path: str | Path) -> list[tuple[dict, dict]]:
    """Mapping JSON -> ordered (baseline_state, refactored_state) pairs."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = payload.get("states", payload if isinstance(payload, list) else [])
    return [(entry["baseline_state"], entry["refactored_state"])
            for entry in entries]


def _initial_state(spec):
    return {variable.name: variable.initial
            for variable in spec.state_variables}


def _freeze(state: dict) -> tuple:
    return tuple(sorted((key, json.dumps(value, sort_keys=True))
                        for key, value in state.items()))


def _successors(spec, state: dict) -> list[dict]:
    result = []
    for operation in spec.operations:
        if guards_hold(operation, state):
            result.append(apply_effects(operation, state))
    return result


def _reachable_states(spec) -> dict[tuple, dict]:
    """Frozen-key -> concrete state over the machine's reachable space."""
    if state_space_upper_bound(spec) > MAX_STATE_SPACE:
        raise ValueError("state space exceeds the bounded equivalence limit")
    seen = {}
    queue = deque([_initial_state(spec)])
    seen[_freeze(_initial_state(spec))] = _initial_state(spec)
    while queue:
        current = queue.popleft()
        for nxt in _successors(spec, current):
            key = _freeze(nxt)
            if key not in seen:
                seen[key] = nxt
                queue.append(nxt)
    return seen


def _format_state(state: dict) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(state.items()))


def prove_equivalence(baseline: str | Path, refactored: str | Path,
                      mapping: str | Path) -> dict:
    """Exhaustive bounded bisimulation under the reviewer's state mapping."""
    try:
        left = _load_domain(baseline)
        right = _load_domain(refactored)
        pairs = load_state_mapping(mapping)
    except (OSError, ValueError, KeyError) as exc:
        return {"status": "EQUIVALENCE_FAILED", "claim": "NO_PROOF",
                "reason": f"invalid input: {exc}"}
    try:
        left_states = _reachable_states(left)
        right_states = _reachable_states(right)
    except ValueError as exc:
        return {"status": "EQUIVALENCE_FAILED", "claim": "NO_PROOF",
                "reason": str(exc)}

    relation = {}
    for left_state, right_state in pairs:
        key = _freeze(left_state)
        if key in relation and relation[key] != right_state:
            return {"status": "EQUIVALENCE_FAILED", "claim": "NO_PROOF",
                    "reason": f"mapping is not functional at {_format_state(left_state)}"}
        relation[key] = right_state
    reverse = {}
    for left_key, right_state in relation.items():
        right_key = _freeze(right_state)
        if right_key in reverse:
            return {"status": "EQUIVALENCE_FAILED", "claim": "NO_PROOF",
                    "reason": "mapping is not injective; one refactored state "
                              "maps from two baseline states"}
        reverse[right_key] = left_key

    # every reachable baseline state must be mapped (else the machines are
    # not comparable through this relation at all)
    for key, state in left_states.items():
        if key not in relation:
            return {"status": "EQUIVALENCE_FAILED", "claim": "NO_PROOF",
                    "reason": f"reachable baseline state {_format_state(state)} "
                              "is absent from the mapping"}

    checked = 0
    for left_key, left_state in left_states.items():
        right_state = relation[left_key]
        right_key = _freeze(right_state)
        if right_key not in right_states:
            return {"status": "EQUIVALENCE_FAILED", "claim": "NO_PROOF",
                    "reason": f"mapped state {_format_state(right_state)} is not "
                              "reachable in the refactored machine"}
        left_next = {_freeze(nxt) for nxt in _successors(left, left_state)}
        right_next = {_freeze(nxt) for nxt in _successors(right, right_state)}
        # every successor of a reachable state is itself reachable, so the
        # all-reachable-states-mapped check above already guarantees each
        # successor has a relation entry — no per-successor guard needed.
        mapped_left_next = {_freeze(relation[key]) for key in left_next}
        if mapped_left_next != right_next:
            missing = right_next - mapped_left_next or mapped_left_next - right_next
            sample = ", ".join(_format_state(dict(key)) for key in sorted(missing)[:3])
            return {"status": "EQUIVALENCE_FAILED", "claim": "NO_PROOF",
                    "reason": f"Missing transition for state "
                              f"{_format_state(right_state)}: successor set "
                              f"mismatch ({sample})"}
        checked += 1

    return {"status": "EQUIVALENCE_PROVED",
            "claim": "BEHAVIORAL_EQUIVALENCE_PROVED",
            "scope": "bounded_state_space_bisimulation",
            "checked_pairs": checked,
            "baseline_reachable": len(left_states),
            "refactored_reachable": len(right_states),
            "heap_equivalence_proved": False,
            "note": "complete for the two bounded V2 machines; says nothing "
                    "about Java heap topology, timing, or I/O"}
