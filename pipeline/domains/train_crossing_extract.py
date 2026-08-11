# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed AST adapter for the train-road crossing state machine."""
from __future__ import annotations

import re

from ..extract_tla_ir import UnsupportedJmlSemantics, extract_method_transition_ir
from ..jml_ast import BinaryExpr, FieldAccess, IntegerLiteral
from ..transition_ir import AssignmentIR, MethodTransitionIR
from .train_crossing import TrainRoadCrossingOperationIR, TrainRoadCrossingTlaModel


ORDER = ["trainApproaches", "lowerGate", "trainEnters", "trainLeaves",
         "raiseGate", "carCrosses", "carLeaves"]
_METHOD = re.compile(
    r"(?P<contracts>(?:\s*//@[^\n]*\n)+)\s*public\s+void\s+"
    r"(?P<name>trainApproaches|lowerGate|trainEnters|trainLeaves|raiseGate|carCrosses|carLeaves)"
    r"\s*\((?P<params>[^)]*)\)\s*\{", re.I)

EXPECTED = {
    "trainApproaches": ("train_pos", 1, ["train_is_away"], "move_train_approaching"),
    "lowerGate": ("gate_state", 1,
                  ["train_is_approaching", "gate_is_up", "crossing_is_clear"], "set_gate_down"),
    "trainEnters": ("train_pos", 2,
                    ["train_is_approaching", "gate_is_down"], "move_train_crossing"),
    "trainLeaves": ("train_pos", 3, ["train_is_crossing"], "move_train_past"),
    "raiseGate": ("gate_state", 0, ["train_is_past", "gate_is_down"], "set_gate_up"),
    "carCrosses": ("car_pos", 1, ["gate_is_up", "car_is_waiting"], "move_car_crossing"),
    "carLeaves": ("car_pos", 0, ["car_is_crossing"], "move_car_waiting"),
}
GUARDS = {
    ("train_pos", "eq", 0): "train_is_away",
    ("train_pos", "eq", 1): "train_is_approaching",
    ("train_pos", "eq", 2): "train_is_crossing",
    ("train_pos", "eq", 3): "train_is_past",
    ("gate_state", "eq", 0): "gate_is_up",
    ("gate_state", "eq", 1): "gate_is_down",
    ("car_pos", "eq", 0): "car_is_waiting",
    ("car_pos", "eq", 1): "car_is_crossing",
}


def recognizes_train_crossing(code: str) -> bool:
    lowered = code.lower()
    return all(re.search(rf"\b{name.lower()}\s*\(", lowered) for name in ORDER)


def _constant_assignment(effect: AssignmentIR, field: str, value: int) -> bool:
    return (effect.target.receiver == "this" and effect.target.field == field and
            isinstance(effect.value, IntegerLiteral) and effect.value.value == value)


def _guard_id(node) -> str | None:
    if not isinstance(node, BinaryExpr) or node.kind != "eq":
        return None
    if isinstance(node.left, FieldAccess) and isinstance(node.right, IntegerLiteral):
        return GUARDS.get((node.left.field, node.kind, node.right.value))
    if isinstance(node.right, FieldAccess) and isinstance(node.left, IntegerLiteral):
        return GUARDS.get((node.right.field, node.kind, node.left.value))
    return None


def _map(transition: MethodTransitionIR) -> tuple[TrainRoadCrossingOperationIR, list[dict]]:
    field, value, required_guards, effect_id = EXPECTED[transition.name]
    if len(transition.success_effects) != 1 or not _constant_assignment(
            transition.success_effects[0], field, value):
        raise UnsupportedJmlSemantics(f"No reviewed effect mapping for {transition.name}")
    frames = [item.field for item in transition.frame if item.receiver == "this"]
    findings = []
    if frames != [field]:
        findings.append({"code": "frame_mismatch", "operation": transition.name,
                         "message": f"{transition.name} may modify only {field}"})
    guards = [value for node in transition.guards if (value := _guard_id(node))]
    # car_is_waiting is also the crossing_is_clear architectural guard on LowerGate.
    if transition.name == "lowerGate" and "car_is_waiting" in guards:
        guards[guards.index("car_is_waiting")] = "crossing_is_clear"
    missing = set(required_guards) - set(guards)
    if missing:
        findings.append({"code": "missing_guard", "operation": transition.name,
                         "message": "Missing safety guards: " + ", ".join(sorted(missing))})
    return TrainRoadCrossingOperationIR(operation=transition.name,
        guard_ids=required_guards if not missing else guards, effect_id=effect_id,
        frame_ids=[field] if frames == [field] else []), findings


def extract_train_crossing_model(code: str, clarifications: str,
                                 abstraction: str | None = None):
    del clarifications
    if abstraction not in {None, "atomic_operations"}:
        raise UnsupportedJmlSemantics("Train crossing supports only atomic_operations")
    matches = {match.group("name").lower(): match for match in _METHOD.finditer(code)}
    if set(matches) != {name.lower() for name in ORDER}:
        raise UnsupportedJmlSemantics("Train crossing requires all seven reviewed void operations")
    fields = {"train_pos", "gate_state", "car_pos"}
    transitions, operations, findings = [], [], []
    for name in ORDER:
        match = matches[name.lower()]
        transition = extract_method_transition_ir(name, "void", match.group("params"),
            match.group("contracts"), fields,
            {"train_pos": "trainPos", "gate_state": "gateState", "car_pos": "carPos"})
        operation, issues = _map(transition)
        transitions.append(transition)
        operations.append(operation)
        findings.extend(issues)
    return TrainRoadCrossingTlaModel(operations=operations, transitions=transitions), findings
