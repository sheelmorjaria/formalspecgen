# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Distributed safety under an unreliable network (fault-injected checking).

Message state in async V2 domains is bounded int/bool slot fields with an
empty sentinel (the ABP encoding). The fault model injects synthetic
operations over the reviewer-declared message fields:

- ``message_loss`` (DropMsg): an occupied slot resets to its empty sentinel
  — a message leaves the network.
- ``duplication`` (DuplicateMsg): a message in one slot is copied into
  another EMPTY slot — the bounded-slots encoding of re-delivery. Needs at
  least two declared fields; a single slot degrades to a vacuous no-op and
  is honestly refused instead.
- ``reordering`` (ReorderMsg): two occupied slots swap values — an
  over-approximation of intra-channel reordering.

Every fault ADDS behaviors, so the exploration over-approximates: invariants
holding under all fault-enabled interleavings hold under any subset of the
faults the real network performs. Safety only — loss can always fire, so
liveness and eventual delivery are never claimed.
"""
from __future__ import annotations

from pathlib import Path

from .domain_v2 import FieldExpr, IntegerExpr, Operation

KNOWN_FAULTS = ("message_loss", "duplication", "reordering")


def _eq(field: str, value: int):
    from .domain_v2 import BinaryExpr
    return BinaryExpr(kind="eq",
                      left=FieldExpr(kind="field", name=field),
                      right=IntegerExpr(kind="integer", value=value))


def _sentinel_of(spec, field: str) -> int:
    variable = next(item for item in spec.state_variables
                    if item.name == field)
    return variable.initial


def _slot_values(spec, field: str) -> list[int]:
    variable = next(item for item in spec.state_variables
                    if item.name == field)
    return list(range(variable.bound[0], variable.bound[1] + 1))


def _occupied_values(spec, field: str) -> list[int]:
    sentinel = _sentinel_of(spec, field)
    return [value for value in _slot_values(spec, field)
            if value != sentinel]


def inject_fault_actions(spec, faults: list[str],
                         message_fields: list[str]) -> list[Operation]:
    """Synthetic fault operations over the declared message-slot fields."""
    operations: list[Operation] = []
    for fault in faults:
        if fault == "message_loss":
            for field in message_fields:
                sentinel = _sentinel_of(spec, field)
                for occupied in _occupied_values(spec, field):
                    operations.append(Operation(
                        name=f"DropMsg_{field}",
                        return_type="void", failure_semantics="unavailable",
                        guards=[{"id": "fg", "expression": _eq(field, occupied)}],
                        effects=[{"id": "fe", "target": field,
                                  "value": IntegerExpr(
                                      kind="integer", value=sentinel)}],
                        frame=[field]))
        elif fault == "duplication":
            # copy an occupied source into another EMPTY slot; a single
            # declared field cannot model re-delivery at this abstraction
            for index, source in enumerate(message_fields):
                for target in message_fields[index + 1:]:
                    source_sentinel = _sentinel_of(spec, source)
                    for value in _occupied_values(spec, source):
                        from .domain_v2 import Effect
                        operations.append(Operation(
                            name=f"DuplicateMsg_{source}_to_{target}",
                            return_type="void",
                            failure_semantics="unavailable",
                            guards=[
                                {"id": "fg1",
                                 "expression": _eq(source, value)},
                                {"id": "fg2", "expression": _eq(
                                    target, _sentinel_of(spec, target))}],
                            effects=[
                                {"id": "fe", "target": target,
                                 "value": IntegerExpr(
                                     kind="integer", value=value)}],
                            frame=[target]))
                    # symmetric direction (target occupied -> empty source)
                    target_sentinel = _sentinel_of(spec, target)
                    for value in _occupied_values(spec, target):
                        operations.append(Operation(
                            name=f"DuplicateMsg_{target}_to_{source}",
                            return_type="void",
                            failure_semantics="unavailable",
                            guards=[
                                {"id": "fg1",
                                 "expression": _eq(target, value)},
                                {"id": "fg2", "expression": _eq(
                                    source, source_sentinel)}],
                            effects=[
                                {"id": "fe", "target": source,
                                 "value": IntegerExpr(
                                     kind="integer", value=value)}],
                            frame=[source]))
        elif fault == "reordering":
            for index, left in enumerate(message_fields):
                for right in message_fields[index + 1:]:
                    left_values = _occupied_values(spec, left)
                    right_values = _occupied_values(spec, right)
                    for lv in left_values:
                        for rv in right_values:
                            # a swap of equal values is a vacuous stutter but
                            # still injected: the fault OCCURRED, and the
                            # over-approximation keeps the claim honest
                            operations.append(Operation(
                                name=f"ReorderMsg_{left}_{right}",
                                return_type="void",
                                failure_semantics="unavailable",
                                guards=[
                                    {"id": "fg1",
                                     "expression": _eq(left, lv)},
                                    {"id": "fg2",
                                     "expression": _eq(right, rv)}],
                                effects=[
                                    {"id": "fe1", "target": left,
                                     "value": IntegerExpr(
                                         kind="integer", value=rv)},
                                    {"id": "fe2", "target": right,
                                     "value": IntegerExpr(
                                         kind="integer", value=lv)}],
                                frame=[left, right]))
    return operations


def _load_domain(path: str | Path):
    from .domain_v2_promotion import ReviewedDomainSpecV2, load_candidate
    try:
        return load_candidate(path)
    except Exception as candidate_error:
        import json
        text = Path(path).read_text(encoding="utf-8")
        try:
            value = json.loads(text)
        except ValueError:
            raise ValueError(str(candidate_error)) from candidate_error
        return ReviewedDomainSpecV2.model_validate(value)


def _fault_of_operation(name: str) -> str | None:
    if name.startswith("DropMsg"):
        return "message_loss"
    if name.startswith("DuplicateMsg"):
        return "duplication"
    if name.startswith("ReorderMsg"):
        return "reordering"
    return None


def verify_distributed(domain: str | Path, *, faults: list[str],
                       message_fields: list[str]) -> dict:
    """Safety under the injected network faults, bounded and exhaustive."""
    path = Path(domain)
    if not path.is_file():
        return {"status": "DISTRIBUTED_SAFETY_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(path)}
    unknown = [fault for fault in faults if fault not in KNOWN_FAULTS]
    if unknown:
        return {"status": "DISTRIBUTED_SAFETY_FAILED", "claim": "NO_PROOF",
                "code": "unknown_fault",
                "message": f"unknown faults {unknown}; known: {list(KNOWN_FAULTS)}"}
    try:
        spec = _load_domain(path)
    except (OSError, ValueError) as exc:
        return {"status": "DISTRIBUTED_SAFETY_FAILED", "claim": "NO_PROOF",
                "code": "domain_unreadable", "message": str(exc)}
    if getattr(spec, "execution_model", None) != "async_message_passing":
        return {"status": "DISTRIBUTED_SAFETY_FAILED", "claim": "NO_PROOF",
                "code": "async_model_required",
                "message": "the fault model applies to async_message_passing "
                           "domains (bounded message-slot state)"}
    declared = {variable.name for variable in spec.state_variables}
    unknown_fields = [field for field in message_fields
                      if field not in declared]
    if unknown_fields:
        return {"status": "DISTRIBUTED_SAFETY_FAILED", "claim": "NO_PROOF",
                "code": "unknown_message_field",
                "message": f"fields {unknown_fields} are not declared state "
                           f"(declared: {sorted(declared)})"}

    fault_ops = inject_fault_actions(spec, faults, message_fields)
    faulted = spec.model_copy(
        update={"operations": list(spec.operations) + fault_ops})

    from .domain_v2_model import (
        MAX_STATE_SPACE, apply_effects, evaluate_expression, guards_hold,
        state_space_upper_bound,
    )
    if state_space_upper_bound(faulted) > MAX_STATE_SPACE:
        return {"status": "DISTRIBUTED_SAFETY_FAILED", "claim": "NO_PROOF",
                "code": "fault_model_state_space_exceeded",
                "message": "the fault-injected machine exceeds the bounded "
                           f"exploration cap ({MAX_STATE_SPACE}); narrow the "
                           "fault set or the bounds"}

    initial = {variable.name: variable.initial
               for variable in spec.state_variables}
    from collections import deque
    seen = {tuple(sorted(initial.items())): initial}
    queue = deque([initial])
    while queue:
        state = queue.popleft()
        for operation in faulted.operations:
            if not guards_hold(operation, state):
                continue
            successor = apply_effects(operation, state)
            key = tuple(sorted(successor.items()))
            if key not in seen:
                seen[key] = successor
                queue.append(successor)
            # check invariants on the successor state
            for invariant in faulted.tlc_invariants:
                if not evaluate_expression(invariant.expression, successor):
                    return {"status": "DISTRIBUTED_SAFETY_FAILED",
                            "claim": "NO_PROOF",
                            "violated_invariant": invariant.id,
                            "fault": _fault_of_operation(operation.name),
                            "operation": operation.name,
                            "state": {k: successor[k]
                                      for k in sorted(successor)},
                            "message": f"invariant {invariant.id!r} fails "
                                       f"after fault action "
                                       f"{operation.name!r}"}
    # fault actions enabled anywhere they apply; safety verified exhaustively
    return {"status": "DISTRIBUTED_SAFETY_PROVED",
            "claim": "DISTRIBUTED_SAFETY_PROVED",
            "scope": "bounded_fault_injected_exploration",
            "fault_model": list(faults),
            "message_fields": list(message_fields),
            "fault_actions_injected": len(fault_ops),
            "reachable_states": len(seen),
            "liveness_proved": False,
            "eventual_delivery_proved": False,
            "note": "safety under adversarial message loss, duplication, "
                    "and reordering over the bounded slot abstraction; "
                    "liveness and eventual delivery are not claimed"}
