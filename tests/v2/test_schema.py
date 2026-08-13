# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

import pytest
from pydantic import ValidationError

from pipeline.domain_v2 import DomainSpecV2


def minimal_domain() -> dict:
    return {
        "schema_version": 2,
        "review_status": "unreviewed",
        "domain_name": "ElevatorController",
        "module_name": "elevator_controller",
        "actors": 2,
        "state_variables": [
            {"kind": "int", "name": "current_floor", "bound": [0, 4], "initial": 0},
            {"kind": "bool", "name": "door_open", "initial": False},
        ],
        "operations": [{
            "name": "startMoveUp",
            "return_type": "void",
            "failure_semantics": "unavailable",
            "guards": [{
                "id": "below_top_floor",
                "expression": {
                    "kind": "lt",
                    "left": {"kind": "field", "name": "current_floor"},
                    "right": {"kind": "integer", "value": 4},
                },
            }],
            "effects": [{
                "id": "increment_floor",
                "target": "current_floor",
                "value": {
                    "kind": "add",
                    "left": {"kind": "old", "expression": {
                        "kind": "field", "name": "current_floor"}},
                    "right": {"kind": "integer", "value": 1},
                },
            }],
            "frame": ["current_floor"],
        }],
        "tlc_invariants": [{
            "id": "FloorWithinBounds",
            "expression": {
                "kind": "gte",
                "left": {"kind": "field", "name": "current_floor"},
                "right": {"kind": "integer", "value": 0},
            },
        }],
    }


def test_rejects_stringly_typed_expression_and_parses_recursive_ast():
    value = minimal_domain()
    value["operations"][0]["guards"][0]["expression"] = "current_floor < 4"
    with pytest.raises(ValidationError):
        DomainSpecV2.model_validate(value)

    parsed = DomainSpecV2.model_validate(minimal_domain())
    expression = parsed.operations[0].effects[0].value
    assert expression.kind == "add"
    assert expression.left.kind == "old"
    assert expression.left.expression.kind == "field"


def test_parses_recursive_not_and_validates_its_field_references():
    value = minimal_domain()
    value["tlc_invariants"][0]["expression"] = {
        "kind": "not", "expression": {"kind": "boolean", "value": False}}
    assert DomainSpecV2.model_validate(value).tlc_invariants[0].expression.kind == "not"
    value["tlc_invariants"][0]["expression"] = {
        "kind": "not", "expression": {"kind": "field", "name": "missing"}}
    with pytest.raises(ValidationError, match="invariant.*undeclared"):
        DomainSpecV2.model_validate(value)


def test_boolean_state_rejects_integer_bounds():
    value = minimal_domain()
    value["state_variables"][1]["bound"] = [0, 1]
    with pytest.raises(ValidationError):
        DomainSpecV2.model_validate(value)


def test_false_and_stutter_requires_boolean_return_type():
    value = minimal_domain()
    value["operations"][0]["failure_semantics"] = "false_and_stutter"
    with pytest.raises(ValidationError, match="boolean return type"):
        DomainSpecV2.model_validate(value)

    value["operations"][0]["return_type"] = "boolean"
    parsed = DomainSpecV2.model_validate(value)
    assert parsed.operations[0].failure_semantics == "false_and_stutter"


def test_initial_integer_value_must_be_inside_bounds():
    value = minimal_domain()
    value["state_variables"][0]["initial"] = 5
    with pytest.raises(ValidationError, match="initial value must be within bounds"):
        DomainSpecV2.model_validate(value)


def test_schema_rejects_unknown_fields_and_invalid_version():
    value = minimal_domain()
    value["unexpected"] = True
    with pytest.raises(ValidationError):
        DomainSpecV2.model_validate(value)
    value = minimal_domain()
    value["schema_version"] = 1
    with pytest.raises(ValidationError):
        DomainSpecV2.model_validate(value)


def test_rejects_reversed_bounds_and_invalid_safe_names():
    value = minimal_domain()
    value["state_variables"][0]["bound"] = [4, 4]
    with pytest.raises(ValidationError, match="lower < upper"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain(); value["domain_name"] = "not Pascal"
    with pytest.raises(ValidationError, match="PascalCase"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain(); value["module_name"] = "../escape"
    with pytest.raises(ValidationError, match="lower-case"):
        DomainSpecV2.model_validate(value)


def test_exception_metadata_is_complete_and_exclusive():
    value = minimal_domain()
    value["operations"][0]["failure_semantics"] = "exception"
    with pytest.raises(ValidationError, match="exception_type"):
        DomainSpecV2.model_validate(value)
    value["operations"][0]["exception_type"] = "IllegalStateException"
    value["operations"][0]["exception_trigger"] = {
        "kind": "boolean", "value": True}
    assert DomainSpecV2.model_validate(value).operations[0].exception_type == \
        "IllegalStateException"
    value = minimal_domain()
    value["operations"][0]["exception_type"] = "IllegalStateException"
    with pytest.raises(ValidationError, match="only for exception"):
        DomainSpecV2.model_validate(value)


@pytest.mark.parametrize("group", ["state_variables", "operations", "tlc_invariants"])
def test_domain_member_names_are_unique(group):
    value = minimal_domain()
    value[group].append(dict(value[group][0]))
    with pytest.raises(ValidationError, match="must be unique"):
        DomainSpecV2.model_validate(value)


def test_rejects_unsafe_reserved_and_undeclared_names_before_rendering():
    value = minimal_domain()
    value["operations"][0]["name"] = "Bad == FALSE"
    with pytest.raises(ValidationError, match="safe identifier"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain()
    value["state_variables"][0]["name"] = "Next"
    with pytest.raises(ValidationError, match="reserved TLA"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain()
    value["operations"][0]["guards"][0]["expression"]["left"]["name"] = "missing"
    with pytest.raises(ValidationError, match="undeclared state"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain(); value["tlc_invariants"][0]["id"] = "TypeOK"
    with pytest.raises(ValidationError, match="collides"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain()
    value["tlc_invariants"][0]["expression"]["left"]["name"] = "missing"
    with pytest.raises(ValidationError, match="invariant.*undeclared"):
        DomainSpecV2.model_validate(value)


def test_rejects_incomplete_duplicate_frames_ids_and_generated_action_collisions():
    value = minimal_domain(); value["operations"][0]["frame"] = []
    with pytest.raises(ValidationError, match="framed field"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain(); value["operations"][0]["frame"] *= 2
    with pytest.raises(ValidationError, match="frame fields must be unique"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain()
    value["operations"][0]["effects"][0]["id"] = \
        value["operations"][0]["guards"][0]["id"]
    with pytest.raises(ValidationError, match="guard/effect IDs"):
        DomainSpecV2.model_validate(value)
    value = minimal_domain()
    value["operations"][0]["return_type"] = "boolean"
    value["operations"][0]["failure_semantics"] = "false_and_stutter"
    collision = dict(value["operations"][0])
    collision.update(name="startMoveUpSuccess", return_type="void",
                     failure_semantics="unavailable")
    value["operations"].append(collision)
    with pytest.raises(ValidationError, match="collides with a TLA"):
        DomainSpecV2.model_validate(value)
