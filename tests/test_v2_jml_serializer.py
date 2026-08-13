# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json

import pytest

from pipeline.domain_v2 import (
    BinaryExpr, BooleanExpr, BoolStateVariable, FieldExpr, IntegerExpr, NotExpr, OldExpr,
    DomainSpecV2,
)
from pipeline.extract_tla_ir import UnsupportedJmlSemantics
from pipeline.v2_jml_serializer import (
    canonical_guard_expressions, java_method_name, render_class, render_expression,
    render_getter, render_operation,
    render_reviewed_v2_file, render_state_variable,
)
from pipeline.v2_invariants import _normalize_comparison


def smart_lock_value():
    field = lambda name: {"kind": "field", "name": name}
    integer = lambda value: {"kind": "integer", "value": value}
    eq = lambda left, right: {"kind": "eq", "left": left, "right": right}
    return {
        "schema_version": 2, "review_status": "unreviewed",
        "domain_name": "SmartLock", "module_name": "smart_lock", "actors": 1,
        "state_variables": [
            {"kind": "int", "name": "door_state", "bound": [0, 1], "initial": 1},
            {"kind": "int", "name": "lock_state", "bound": [0, 1], "initial": 0},
        ],
        "operations": [{
            "name": "CloseDoor", "return_type": "void", "failure_semantics": "unavailable",
            "guards": [{"id": "open", "expression": eq(field("door_state"), integer(0))}],
            "effects": [{"id": "close", "target": "door_state", "value": integer(1)}],
            "frame": ["door_state"],
        }],
        "tlc_invariants": [{"id": "LockOnlyWhenClosed", "expression": {
            "kind": "implies", "left": eq(field("lock_state"), integer(1)),
            "right": eq(field("door_state"), integer(1))}}],
    }


def test_expression_ast_serialization_and_fail_closed_boundary():
    field = FieldExpr(name="door_state")
    assert render_expression(field) == "door_state"
    assert render_expression(IntegerExpr(value=1)) == "1"
    assert render_expression(BooleanExpr(value=True)) == "true"
    assert render_expression(BooleanExpr(value=False)) == "false"
    assert render_expression(OldExpr(expression=field)) == r"\old(door_state)"
    assert render_expression(BinaryExpr(kind="eq", left=field,
        right=IntegerExpr(value=1))) == "(door_state == 1)"
    assert render_expression(BinaryExpr(kind="implies", left=field,
        right=FieldExpr(name="lock_state"))) == "(door_state ==> lock_state)"
    assert render_expression(NotExpr(expression=field)) == "!(door_state)"
    with pytest.raises(UnsupportedJmlSemantics, match="unsupported V2 expression node"):
        render_expression(object())
    unsupported = BinaryExpr.model_construct(
        kind="multiset", left=field, right=IntegerExpr(value=1))
    with pytest.raises(UnsupportedJmlSemantics, match="unsupported V2 expression kind"):
        render_expression(unsupported)


def test_state_bounds_custom_invariant_and_constructor_serialization():
    spec = DomainSpecV2.model_validate(smart_lock_value())
    rendered = render_state_variable(spec.state_variables[0])
    assert rendered[0] == "    private /*@ spec_public @*/ int door_state;"
    assert rendered[1] == "    //@ public invariant 0 <= door_state && door_state <= 1;"
    assert render_state_variable(BoolStateVariable(name="enabled", initial=False)) == [
        "    private /*@ spec_public @*/ boolean enabled;"]
    with pytest.raises(UnsupportedJmlSemantics, match="unsupported V2 state variable"):
        render_state_variable(object())
    code = render_class(spec)
    assert "//@ public invariant ((lock_state == 1) ==> (door_state == 1));" in code
    assert "//@ ensures door_state == 1 && lock_state == 0;" in code
    assert r"//@ assignable \nothing;" in code
    assert "this.door_state = 1;" in code
    assert "public /*@ pure @*/ int getDoorState() { return door_state; }" in code
    assert r"//@ ensures \result == lock_state;" in code


def test_invariant_comparison_normalization_handles_strict_integer_bounds():
    field = FieldExpr(name="door_state")
    lower = _normalize_comparison(BinaryExpr(
        kind="gt", left=field, right=IntegerExpr(value=0)))
    upper = _normalize_comparison(BinaryExpr(
        kind="gt", left=IntegerExpr(value=2), right=field))
    assert lower == BinaryExpr(
        kind="lte", left=IntegerExpr(value=1), right=field)
    assert upper == BinaryExpr(
        kind="lte", left=field, right=IntegerExpr(value=1))


def test_void_and_boolean_operation_contracts_include_frames_and_stutter():
    spec = DomainSpecV2.model_validate(smart_lock_value())
    void = render_operation(spec.operations[0], ["door_state", "lock_state"])
    assert "//@ requires (door_state == 0);" in void
    assert "//@ assignable door_state;" in void
    assert "//@ ensures door_state == 1;" in void
    assert "public void closeDoor() {}" in void

    value = smart_lock_value()
    value["operations"][0].update(
        name="TryClose", return_type="boolean", failure_semantics="false_and_stutter")
    boolean_spec = DomainSpecV2.model_validate(value)
    boolean = render_operation(boolean_spec.operations[0], ["door_state", "lock_state"])
    assert r"//@ ensures \result <==> ((\old(door_state) == 0));" in boolean
    assert r"//@ ensures \result ==> (door_state == 1);" in boolean
    assert r"door_state == \old(door_state) && lock_state == \old(lock_state)" in boolean
    assert "public boolean tryClose()" in boolean


def test_java_names_and_typed_getters_are_deterministic_and_fail_closed():
    assert java_method_name("CloseDoor") == "closeDoor"
    assert java_method_name("alreadyLower") == "alreadyLower"
    with pytest.raises(UnsupportedJmlSemantics, match="cannot be empty"):
        java_method_name("")
    assert "boolean getEnabled()" in render_getter(
        BoolStateVariable(name="enabled", initial=False))
    with pytest.raises(UnsupportedJmlSemantics, match="unsupported V2 getter"):
        render_getter(object())


def test_equivalent_integer_guards_are_canonicalized_and_deduplicated():
    value = smart_lock_value()
    value["operations"][0]["guards"] = [
        {"id": "strict", "expression": {"kind": "lt",
            "left": {"kind": "field", "name": "door_state"},
            "right": {"kind": "integer", "value": 5}}},
        {"id": "inclusive", "expression": {"kind": "lte",
            "left": {"kind": "field", "name": "door_state"},
            "right": {"kind": "integer", "value": 4}}},
    ]
    operation = DomainSpecV2.model_validate(value).operations[0]
    canonical = canonical_guard_expressions(operation)
    assert len(canonical) == 1
    assert canonical[0].kind == "lte" and canonical[0].right.value == 4
    rendered = render_operation(operation, ["door_state", "lock_state"])
    assert rendered.count("requires") == 1
    assert "(door_state <= 4)" in rendered


def test_effect_field_references_are_rendered_in_pre_state():
    value = smart_lock_value()
    value["operations"][0]["effects"][0]["value"] = {
        "kind": "sub", "left": {"kind": "field", "name": "door_state"},
        "right": {"kind": "integer", "value": 1}}
    spec = DomainSpecV2.model_validate(value)
    assert r"door_state == (\old(door_state) - 1)" in render_class(spec)


def test_full_class_is_stable_and_reviewed_loader_rejects_candidate(tmp_path):
    spec = DomainSpecV2.model_validate(smart_lock_value())
    code = render_class(spec)
    assert code.startswith(
        "public class SmartLock {\n    private /*@ spec_public @*/ int door_state;")
    assert code.endswith("}\n")
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps(smart_lock_value()))
    with pytest.raises(ValueError):
        render_reviewed_v2_file(candidate)


def test_unsupported_operation_semantics_fail_closed():
    value = smart_lock_value()
    value["operations"][0].update(
        failure_semantics="exception", exception_type="E",
        exception_trigger={"kind": "boolean", "value": True})
    spec = DomainSpecV2.model_validate(value)
    with pytest.raises(UnsupportedJmlSemantics, match="unsupported V2 operation semantics"):
        render_class(spec)
