# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""AST-structural semantic adapter for addStock/reserve/release contracts."""
from __future__ import annotations

import re

from ..extract_tla_ir import UnsupportedJmlSemantics, extract_method_transition_ir
from ..jml_ast import BinaryExpr, FieldAccess, OldValue, Parameter
from ..transition_ir import AssignmentIR, MethodTransitionIR
from .inventory import InventoryOperationIR, InventoryTlaModel


_METHOD = re.compile(
    r"(?P<contracts>(?:\s*//@[^\n]*\n)+)\s*public\s+(?:static\s+)?"
    r"(?P<return>boolean|void|int|long)\s+(?P<name>addStock|reserve|release)\s*"
    r"\((?P<params>[^)]*)\)\s*\{", re.I,
)


def recognizes_inventory(code: str) -> bool:
    lowered = code.lower()
    return (all(re.search(rf"\b{name}\s*\(", lowered)
                for name in ("addstock", "reserve", "release")) and
            re.search(r"\b(?:stock|reserved)\b", lowered) is not None)


def _is_field(node, field: str) -> bool:
    return isinstance(node, FieldAccess) and node.receiver == "this" and node.field == field


def _is_old_field(node, field: str) -> bool:
    return isinstance(node, OldValue) and _is_field(node.expression, field)


def _is_parameter(node, name: str = "amount") -> bool:
    return isinstance(node, Parameter) and node.name == name


def _increment(effect: AssignmentIR, field: str) -> bool:
    value = effect.value
    return (_is_field_target(effect, field) and isinstance(value, BinaryExpr) and
            value.kind == "add" and _is_old_field(value.left, field) and
            _is_parameter(value.right))


def _decrement(effect: AssignmentIR, field: str) -> bool:
    value = effect.value
    return (_is_field_target(effect, field) and isinstance(value, BinaryExpr) and
            value.kind == "sub" and _is_old_field(value.left, field) and
            _is_parameter(value.right))


def _is_field_target(effect: AssignmentIR, field: str) -> bool:
    return effect.target.receiver == "this" and effect.target.field == field


def _preserves_field(transition: MethodTransitionIR, field: str) -> bool:
    return any(_is_field_target(effect, field) and _is_old_field(effect.value, field)
               for effect in transition.failure_effects)


def _contains_positive_amount(transition: MethodTransitionIR) -> bool:
    return any(isinstance(guard, BinaryExpr) and guard.kind == "gt" and
               _is_parameter(guard.left) and getattr(guard.right, "value", None) == 0
               for guard in transition.guards)


def _contains_capacity(node, field: str) -> bool:
    if not isinstance(node, BinaryExpr):
        return False
    if node.kind == "lte" and _is_parameter(node.left):
        # amount <= bound - old(field)
        return (isinstance(node.right, BinaryExpr) and node.right.kind == "sub" and
                _is_old_field(node.right.right, field))
    return _contains_capacity(node.left, field) or _contains_capacity(node.right, field)


def _contains_available_stock(node) -> bool:
    if not isinstance(node, BinaryExpr):
        return False
    # amount <= old(stock) - old(reserved)
    if node.kind == "lte" and _is_parameter(node.left):
        return (isinstance(node.right, BinaryExpr) and node.right.kind == "sub" and
                _is_old_field(node.right.left, "stock") and
                _is_old_field(node.right.right, "reserved"))
    return _contains_available_stock(node.left) or _contains_available_stock(node.right)


def _contains_reserved_stock(node) -> bool:
    if not isinstance(node, BinaryExpr):
        return False
    if node.kind == "lte" and _is_parameter(node.left):
        return _is_old_field(node.right, "reserved") or _is_field(node.right, "reserved")
    return _contains_reserved_stock(node.left) or _contains_reserved_stock(node.right)


def _map_operation(transition: MethodTransitionIR) -> tuple[InventoryOperationIR, list[dict]]:
    name = transition.name
    findings = []
    expected = {
        "addStock": ("stock", "increase_stock", "product_stock", _increment),
        "reserve": ("reserved", "reserve_stock", "product_reserved", _increment),
        "release": ("reserved", "release_stock", "product_reserved", _decrement),
    }
    field, effect_id, frame_id, matcher = expected[name]
    if len(transition.success_effects) != 1 or not matcher(transition.success_effects[0], field):
        raise UnsupportedJmlSemantics(f"No reviewed {name} effect AST mapping")
    actual_frame = {(item.receiver, item.field) for item in transition.frame}
    if actual_frame != {("this", field)}:
        findings.append({"code": "frame_mismatch", "operation": name,
                         "message": f"{name} may modify only {field}"})
    if not transition.result_constrained:
        findings.append({"code": "unconstrained_result", "operation": name,
                         "message": "Boolean result does not define success and failure"})
    if not _preserves_field(transition, field):
        findings.append({"code": "failure_changes_state", "operation": name,
                         "message": f"Failed {name} must preserve {field}"})
    guards = []
    if _contains_positive_amount(transition):
        guards.append("positive_amount")
    condition = transition.success_condition
    guard_test = {
        "addStock": lambda: bool(condition and _contains_capacity(condition, "stock")),
        "reserve": lambda: bool(condition and _contains_available_stock(condition)),
        "release": lambda: bool(condition and _contains_reserved_stock(condition)),
    }[name]
    domain_guard = {
        "addStock": "stock_has_capacity", "reserve": "enough_available_stock",
        "release": "enough_reserved_stock",
    }[name]
    if guard_test():
        guards.append(domain_guard)
    for missing in {"positive_amount", domain_guard} - set(guards):
        findings.append({"code": "missing_guard", "operation": name,
                         "message": f"Missing reviewed guard: {missing}"})
    operation = InventoryOperationIR(operation=name, guard_ids=guards,
        effect_id=effect_id, frame_ids=[frame_id] if actual_frame == {("this", field)} else [],
        result_constrained=transition.result_constrained,
        failure_preserves_frame=_preserves_field(transition, field))
    return operation, findings


def extract_inventory_model(code: str, clarifications: str,
                            abstraction: str | None = None) -> tuple[InventoryTlaModel, list[dict]]:
    del clarifications
    if abstraction not in {None, "atomic_operations"}:
        raise UnsupportedJmlSemantics("Inventory currently supports only atomic_operations")
    matches = {match.group("name").lower(): match for match in _METHOD.finditer(code)}
    aliases = {"addstock": "addStock", "reserve": "reserve", "release": "release"}
    if set(matches) != set(aliases):
        raise UnsupportedJmlSemantics("Inventory requires addStock, reserve, and release contracts")
    fields = set(re.findall(
        r"\b(?:private|protected|public)\s+(?:/\*@.*?@\*/\s+)?(?:boolean|int|long)\s+(\w+)\s*;", code))
    transitions = []
    operations = []
    findings = []
    for key in ("addstock", "reserve", "release"):
        match = matches[key]
        transition = extract_method_transition_ir(aliases[key], match.group("return"),
            match.group("params"), match.group("contracts"), fields,
            {"stock": "stock", "reserved": "reserved"})
        operation, operation_findings = _map_operation(transition)
        transitions.append(transition)
        operations.append(operation)
        findings.extend(operation_findings)
    return InventoryTlaModel(operations=operations, transitions=transitions), findings
