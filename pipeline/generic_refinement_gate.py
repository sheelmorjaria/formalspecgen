# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Restricted, deterministic V2 JML-to-action refinement certificates."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .domain_v2 import BinaryExpr as V2Binary, DomainSpecV2, FieldExpr as V2Field
from .domain_v2 import BooleanExpr as V2Boolean, IntegerExpr as V2Integer
from .domain_v2 import NotExpr as V2Not, OldExpr as V2Old
from .extract_tla_ir import UnsupportedJmlSemantics, extract_method_transition_ir
from .jml_ast import BinaryExpr, BooleanLiteral, FieldAccess, IntegerLiteral, OldValue, UnaryExpr
from .implementation import trusted_surface_hash
from .v2_jml_serializer import canonical_guard_expressions, java_method_name
from .v2_refinement import RefinementBoundaryError, load_bound_reviewed_domain


_FIELD = re.compile(r"(?m)^\s*(?:public|private|protected)?\s*(?:/\*@.*?@\*/\s*)?"
                    r"(?:boolean|int|long)\s+([A-Za-z_]\w*)\s*(?:=[^;]+)?;")
_METHOD = re.compile(r"(?P<contracts>(?:\s*//@[^\n]*\n)+)\s*public\s+"
                     r"(?P<modifier>/\*@.*?@\*/\s+)?"
                     r"(?P<return>boolean|void|int|long)\s+(?P<name>[A-Za-z_]\w*)\s*"
                     r"\((?P<params>[^)]*)\)\s*\{")


def _encapsulation_errors(code: str, spec: DomainSpecV2) -> list[str]:
    errors = []
    for state in spec.state_variables:
        java_type = "boolean" if state.kind == "bool" else "int"
        declaration = re.compile(
            rf"(?m)^\s*private\s+/\*@\s*spec_public\s*@\*/\s+"
            rf"{java_type}\s+{re.escape(state.name)}\s*(?:=[^;]+)?;\s*$")
        if not declaration.search(code):
            errors.append(
                f"State field '{state.name}' must be declared private "
                f"/*@ spec_public @*/ {java_type}")
    return errors


def _extract(code: str, fields: set[str]):
    transitions = []
    for match in _METHOD.finditer(code):
        if match["modifier"] and re.search(r"\bpure\b", match["modifier"]):
            continue
        transitions.append(extract_method_transition_ir(
            match["name"], match["return"], match["params"], match["contracts"], fields,
            {field: field for field in fields}))
    return transitions


def _equivalent(v2, jml) -> bool:
    # V2 guards denote pre-state expressions. JML may make that pre-state
    # explicit with \old when the guard appears under a result postcondition.
    if isinstance(jml, OldValue) and not isinstance(v2, V2Old):
        return _equivalent(v2, jml.expression)
    if isinstance(v2, V2Field): return isinstance(jml, FieldAccess) and jml.receiver == "this" and jml.field == v2.name
    if isinstance(v2, V2Integer): return isinstance(jml, IntegerLiteral) and jml.value == v2.value
    if isinstance(v2, V2Boolean): return isinstance(jml, BooleanLiteral) and jml.value == v2.value
    if isinstance(v2, V2Old):
        return _equivalent(v2.expression, jml.expression if isinstance(jml, OldValue) else jml)
    if isinstance(v2, V2Not):
        return isinstance(jml, UnaryExpr) and jml.kind == "not" and \
            _equivalent(v2.expression, jml.operand)
    if isinstance(v2, V2Binary):
        return isinstance(jml, BinaryExpr) and jml.kind == v2.kind and \
            _equivalent(v2.left, jml.left) and _equivalent(v2.right, jml.right)
    return False


def _flatten_v2_and(node):
    if isinstance(node, V2Binary) and node.kind == "and":
        return [*_flatten_v2_and(node.left), *_flatten_v2_and(node.right)]
    return [node]


def generic_v2_refinement_gate(reviewed_path: str | Path, validation_path: str | Path,
                               contract_code: str, implementation_code: str, *,
                               esc_verified: bool, tlc_verified: bool = True) -> dict:
    def fail(code, message, obligations=None):
        return {"status":"FAIL", "code":code, "message":message,
                "source_refinement_proved":False, "obligations":obligations or []}
    if not esc_verified: return fail("esc_not_verified", "Implementation has no deductive proof")
    if not tlc_verified: return fail("tlc_not_verified", "V2 model has no successful TLC result")
    try:
        reviewed = load_bound_reviewed_domain(reviewed_path, validation_path)
        fields = {item.name for item in reviewed.state_variables}
        contract_encapsulation = _encapsulation_errors(contract_code, reviewed)
        implementation_encapsulation = _encapsulation_errors(implementation_code, reviewed)
        if contract_encapsulation or implementation_encapsulation:
            return fail("encapsulation_violation", "; ".join(
                contract_encapsulation + implementation_encapsulation))
        contract = _extract(contract_code, fields); implementation = _extract(implementation_code, fields)
    except RefinementBoundaryError as exc:
        return fail(exc.code, str(exc))
    except (OSError, ValueError, KeyError, UnsupportedJmlSemantics) as exc:
        return fail("unsupported_refinement_boundary", str(exc))
    if not contract or not implementation:
        return fail("empty_transition_surface", "No reviewed JML transition surface was found")
    if [item.model_dump() for item in contract] != [item.model_dump() for item in implementation]:
        return fail("trusted_contract_changed", "Implementation contract transition surface changed")
    by_name = {item.name:item for item in contract}
    expected_methods = {java_method_name(item.name): item for item in reviewed.operations}
    if len(expected_methods) != len(reviewed.operations) or set(by_name) != set(expected_methods):
        return fail("operation_coverage_mismatch", "JML methods and V2 operations are not one-to-one")
    obligations=[]
    for operation in reviewed.operations:
        method_name = java_method_name(operation.name)
        transition=by_name[method_name]
        frame_ok={item.field for item in transition.frame} == set(operation.frame) and \
            all(item.receiver == "this" for item in transition.frame)
        expected_guards=canonical_guard_expressions(operation)
        actual_guards = transition.guards if operation.return_type == "void" else []
        if operation.return_type == "void":
            guard_ok=len(expected_guards)==len(actual_guards) and all(
                _equivalent(left,right) for left,right in zip(expected_guards,actual_guards))
        else:
            combined = expected_guards[0] if expected_guards else None
            for guard in expected_guards[1:]:
                combined=V2Binary(kind="and",left=combined,right=guard)
            guard_ok=not transition.guards and combined is not None and \
                transition.success_condition is not None and _equivalent(combined,transition.success_condition)
        effects={item.target.field:item.value for item in transition.success_effects
                 if item.target.receiver=="this"}
        effect_ok=len(effects)==len(operation.effects) and all(
            effect.target in effects and _equivalent(effect.value,effects[effect.target])
            for effect in operation.effects)
        failure_ok=True
        if operation.failure_semantics=="false_and_stutter":
            failed={item.target.field:item.value for item in transition.failure_effects}
            failure_ok=set(failed)==fields and all(
                isinstance(failed[field],OldValue) and _equivalent(V2Field(name=field),failed[field].expression)
                for field in fields)
        elif transition.failure_effects:
            failure_ok = False
        proved=guard_ok and effect_ok and frame_ok and failure_ok
        obligations.append({"method":method_name,"action":operation.name,
          "pre_state_aligned":guard_ok,"post_state_aligned":effect_ok,"frame_aligned":frame_ok,
          "failure_stutters":failure_ok,"status":"PROVED" if proved else "FAILED"})
    if any(item["status"]!="PROVED" for item in obligations):
        return fail("refinement_obligation_failed", "A restricted simulation obligation failed", obligations)
    contract_hash = trusted_surface_hash(contract_code)
    implementation_hash = hashlib.sha256(implementation_code.encode("utf-8")).hexdigest()
    body={"domain":reviewed.module_name,"scope":"v2_atomic_contract_refinement",
          "accepted_candidate_sha256":reviewed.accepted_candidate_sha256,
          "evidence_sha256":reviewed.accepted_evidence_sha256,
          "trusted_contract_sha256":contract_hash,
          "implementation_sha256":implementation_hash,"obligations":obligations}
    certificate=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"status":"VERIFIED","claim":"SOURCE_MODEL_REFINEMENT",
      "scope":body["scope"],"source_refinement_proved":True,
      "concurrent_linearizability_proved":False,"obligations":obligations,
      "trusted_contract_sha256":contract_hash,
      "implementation_sha256":implementation_hash,
      "certificate_sha256":certificate}
