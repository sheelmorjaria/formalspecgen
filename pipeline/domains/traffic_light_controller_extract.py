"""Fail-closed JML AST adapter for the reviewed traffic-light controller."""
from __future__ import annotations

import re
from ..extract_tla_ir import UnsupportedJmlSemantics, extract_method_transition_ir
from ..jml_ast import BinaryExpr, FieldAccess, IntegerLiteral
from ..transition_ir import AssignmentIR, MethodTransitionIR
from .traffic_light_controller import (
    TrafficLightControllerOperationIR, TrafficLightControllerTlaModel,
)

ORDER = ['turnNsGreen', 'turnNsYellow', 'turnNsRed', 'turnEwGreen', 'turnEwYellow', 'turnEwRed']
REQUIRED_METHODS = [name.lower() for name in ORDER]
_METHOD = re.compile(
    r"(?P<contracts>(?:\s*//@[^\n]*\n)+)\s*public\s+void\s+"
    r"(?P<name>turnNsGreen|turnNsYellow|turnNsRed|turnEwGreen|turnEwYellow|turnEwRed)"
    r"\s*\((?P<params>[^)]*)\)\s*\{", re.I)

EXPECTED = {
    'turnNsGreen': ('ns_light', 2, ['ew_is_red'], 'set_ns_green'),
    'turnNsYellow': ('ns_light', 1, ['ns_is_green'], 'set_ns_yellow'),
    'turnNsRed': ('ns_light', 0, ['ns_is_yellow'], 'set_ns_red'),
    'turnEwGreen': ('ew_light', 2, ['ns_is_red'], 'set_ew_green'),
    'turnEwYellow': ('ew_light', 1, ['ew_is_green'], 'set_ew_yellow'),
    'turnEwRed': ('ew_light', 0, ['ew_is_yellow'], 'set_ew_red'),
}
GUARDS = {
    ('ns_light', 0): 'ns_is_red', ('ns_light', 1): 'ns_is_yellow',
    ('ns_light', 2): 'ns_is_green', ('ew_light', 0): 'ew_is_red',
    ('ew_light', 1): 'ew_is_yellow', ('ew_light', 2): 'ew_is_green',
}

def recognizes_traffic_light_controller(code: str) -> bool:
    matches = {match.group('name').lower() for match in _METHOD.finditer(code)}
    return matches == set(REQUIRED_METHODS)


def diagnose_traffic_light_boundary(code: str) -> list[str]:
    """Explain why a traffic-light-like API cannot enter the reviewed adapter."""
    lowered = code.lower()
    if "trafficlight" not in lowered and not (
            ("nslight" in lowered or "ns_light" in lowered) and
            ("ewlight" in lowered or "ew_light" in lowered)):
        return []
    signatures = re.findall(
        r"\bpublic\s+(void|boolean|int|long)\s+(\w+)\s*\(", code, re.I)
    found = {name for _return_type, name in signatures}
    missing = [name for name in ORDER if name.lower() not in {item.lower() for item in found}]
    details = []
    if missing:
        details.append("missing reviewed operations: " + ", ".join(missing))
    wrong_returns = [name for return_type, name in signatures
                     if name.lower() in set(REQUIRED_METHODS) and return_type.lower() != 'void']
    if wrong_returns:
        details.append("reviewed operations must return void, not boolean: " +
                       ", ".join(sorted(wrong_returns)))
    aliases = sorted(found & {"setNorthSouthGreen", "setEastWestGreen", "resetLights"})
    if aliases:
        details.append("unreviewed three-action API found: " + ", ".join(aliases))
    if "nsLight" in code or "ewLight" in code:
        details.append("reviewed state locations are this.ns_light and this.ew_light")
    if re.search(r"requires\s+(?:nsLight|ewLight)\s*!=\s*2", code):
        details.append("green transitions use a weakened != GREEN guard; the reviewed model requires the opposing light == RED")
    return details


def _constant_assignment(effect: AssignmentIR, field: str, value: int) -> bool:
    return (effect.target.receiver == 'this' and effect.target.field == field and
            isinstance(effect.value, IntegerLiteral) and effect.value.value == value)


def _guard_id(node) -> str | None:
    if not isinstance(node, BinaryExpr) or node.kind != 'eq':
        return None
    if isinstance(node.left, FieldAccess) and isinstance(node.right, IntegerLiteral):
        return GUARDS.get((node.left.field, node.right.value))
    if isinstance(node.right, FieldAccess) and isinstance(node.left, IntegerLiteral):
        return GUARDS.get((node.right.field, node.left.value))
    return None


def _map(transition: MethodTransitionIR) -> tuple[TrafficLightControllerOperationIR, list[dict]]:
    field, value, required_guards, effect_id = EXPECTED[transition.name]
    if len(transition.success_effects) != 1 or not _constant_assignment(
            transition.success_effects[0], field, value):
        raise UnsupportedJmlSemantics(f'No reviewed effect mapping for {transition.name}')
    frames = [item.field for item in transition.frame if item.receiver == 'this']
    guards = [_guard_id(node) for node in transition.guards]
    findings = []
    if frames != [field]:
        findings.append({'code': 'frame_mismatch', 'operation': transition.name,
                         'message': f'{transition.name} may modify only {field}'})
    if None in guards or guards != required_guards:
        findings.append({'code': 'guard_mismatch', 'operation': transition.name,
                         'message': f'Expected exactly {required_guards}, got {guards}'})
    return TrafficLightControllerOperationIR(
        operation=transition.name, guard_ids=required_guards if guards == required_guards else [],
        effect_id=effect_id, frame_ids=[field] if frames == [field] else [],
        result_constrained=True, failure_preserves_frame=True), findings


def _check_initial_state(code: str) -> None:
    constructor = re.search(
        r'(?P<contracts>(?:\s*//@[^\n]*\n)+)\s*public\s+TrafficLightController\s*\(\s*\)',
        code)
    if not constructor:
        raise UnsupportedJmlSemantics('Missing reviewed TrafficLightController constructor contract')
    normalized = re.sub(r'\s+', '', constructor.group('contracts')).lower()
    if not ('ensuresns_light==0&&ew_light==0;' in normalized or
            'ensuresew_light==0&&ns_light==0;' in normalized):
        raise UnsupportedJmlSemantics('Constructor must establish ns_light == 0 and ew_light == 0')


def extract_traffic_light_controller_model(code: str, clarifications: str,
                                           abstraction: str | None):
    del clarifications
    if abstraction not in {None, 'atomic_operations'}:
        raise UnsupportedJmlSemantics(
            'Traffic-light controller supports only atomic_operations')
    _check_initial_state(code)
    matches = {match.group('name').lower(): match for match in _METHOD.finditer(code)}
    if set(matches) != set(REQUIRED_METHODS):
        raise UnsupportedJmlSemantics('Traffic-light controller requires all six reviewed void operations')
    fields = {'ns_light', 'ew_light'}
    transitions, operations, findings = [], [], []
    for name in ORDER:
        match = matches[name.lower()]
        transition = extract_method_transition_ir(
            name, 'void', match.group('params'), match.group('contracts'), fields,
            {'ns_light': 'nsLight', 'ew_light': 'ewLight'})
        operation, issues = _map(transition)
        transitions.append(transition)
        operations.append(operation)
        findings.extend(issues)
    return TrafficLightControllerTlaModel(
        operations=operations, transitions=transitions), findings
