"""Backfill coverage for error branches and helpers in pipeline/staged_architecture.py."""
import json

import pytest

from pipeline.staged_architecture import (
    ComponentFragment,
    OperationFragment,
    StateVariableFragment,
    StagedComponent,
    StagedStateVariable,
    TransitionFragment,
    UseCaseStepFragment,
    assemble_architecture,
    assemble_component_fragments,
    assemble_unified_architecture,
    normalize_transition_fragments,
    parse_component_fragments,
    parse_fragment_list,
    parse_operation_fragments,
    validate_step_bindings,
)


def _operation(name="reserve"):
    return OperationFragment.model_validate({
        "name": name,
        "params": [{"name": "amount", "type": "int"}],
        "requires": "amount > 0",
        "ensures": "reserved",
        "returns": "boolean",
    })


def _transition_dict(operation_name="reserve", target="stock", value=4):
    return {
        "operation_name": operation_name,
        "precondition": {"kind": "gt", "left": {"kind": "field", "name": target},
                         "right": {"kind": "integer", "value": 0}},
        "effects": [{"target": target, "value": {"kind": "integer", "value": value}}],
        "frame": [target],
    }


def _transition(operation_name="reserve"):
    return TransitionFragment.model_validate(_transition_dict(operation_name))


def _staged_component_payload(**overrides):
    payload = {
        "name": "Inventory",
        "type": "core",
        "state_variables": [{"name": "stock", "type": "int", "bound": [0, 5], "initial": 5}],
        "operations": [{"name": "reserve", "params": [],
                        "contract": {"requires": "true", "ensures": "true"}}],
        "transitions": [_transition_dict()],
    }
    payload.update(overrides)
    return payload


def test_staged_state_variable_requires_ordered_bounds():
    with pytest.raises(ValueError, match="state bounds must be ordered"):
        StagedStateVariable(name="stock", type="int", bound=(5, 0))


def test_operation_fragment_rejects_duplicate_parameters():
    duplicate = [{"name": "amount", "type": "int"}, {"name": "amount", "type": "boolean"}]
    with pytest.raises(ValueError, match="operation parameters must be unique"):
        OperationFragment(name="reserve", params=duplicate,
                          requires="amount > 0", ensures="reserved")


def test_state_variable_fragment_rejects_initial_outside_bound():
    with pytest.raises(ValueError, match="initial state value is outside its bound"):
        StateVariableFragment(name="stock", type="int", bound=(0, 5), initial=7)


def test_transition_fragment_rejects_duplicate_frame_fields():
    payload = _transition_dict()
    payload["frame"] = ["stock", "stock"]
    with pytest.raises(ValueError, match="frame fields must be unique"):
        TransitionFragment.model_validate(payload)


def test_validate_step_bindings_rejects_extra_arguments():
    step = UseCaseStepFragment(component="Inventory", operation="reserve",
                               arguments={"amount": "1", "spare": "2"})
    with pytest.raises(ValueError, match="EXTRA_ARGUMENT_BINDING: spare"):
        validate_step_bindings(step, _operation())


def test_staged_component_accepts_declared_transition_and_rejects_shape_errors():
    component = StagedComponent.model_validate(_staged_component_payload())
    assert component.transitions[0].operation_name == "reserve"

    duplicated = _staged_component_payload()
    duplicated["state_variables"].append({"name": "stock", "type": "boolean", "initial": True})
    with pytest.raises(ValueError, match="DUPLICATE_STATE_VARIABLE"):
        StagedComponent.model_validate(duplicated)

    undeclared = _staged_component_payload(transitions=[_transition_dict("release")])
    with pytest.raises(ValueError, match="UNDECLARED_OPERATION_TRANSITION: release"):
        StagedComponent.model_validate(undeclared)


def test_parse_operation_fragments_rejects_invalid_groups_contracts_and_params():
    with pytest.raises(ValueError, match="INVALID_OPERATION_GROUP: Inventory"):
        parse_operation_fragments(json.dumps({"Inventory": {"reserve": {}}}))
    with pytest.raises(ValueError, match="operation contract must be an object"):
        parse_operation_fragments(json.dumps([{"name": "reserve", "contract": "stock > 0"}]))
    with pytest.raises(ValueError, match="UNSUPPORTED_OPERATION_PARAMETER_TYPE"):
        parse_operation_fragments(json.dumps(
            [{"name": "reserve", "params": [{"name": "label", "type": "string"}]}]))


def test_parse_fragment_list_flattens_list_group_and_single_dict_shapes():
    grouped = parse_fragment_list(json.dumps({"Inventory": [
        {"name": "stock", "type": "int", "bound": [0, 5], "initial": 5}]}),
        StateVariableFragment, "state")
    assert grouped[0].name == "stock"

    single_state = parse_fragment_list(json.dumps(
        {"Inventory": {"name": "stock", "type": "int", "bound": [0, 5], "initial": 5}}),
        StateVariableFragment, "state")
    assert single_state[0].name == "stock"

    single_step = parse_fragment_list(json.dumps(
        {"Checkout": {"component": "Inventory", "operation": "reserve"}}),
        UseCaseStepFragment, "use-case")
    assert single_step[0].component == "Inventory"

    sole_list = parse_fragment_list(json.dumps({"Inventory": {"stock_decl": [
        {"name": "stock", "type": "int", "bound": [0, 5], "initial": 5}]}}),
        StateVariableFragment, "state")
    assert sole_list[0].name == "stock"


def test_parse_fragment_list_recursively_collects_nested_keyed_lists():
    nested = parse_fragment_list(json.dumps({"Group": {
        "Inventory": [_transition_dict("reserve")],
        "Warehouse": [_transition_dict("release", target="stock", value=0)],
        "meta": 5}}), TransitionFragment, "transition")
    assert [item.operation_name for item in nested] == ["reserve", "release"]


def test_parse_fragment_list_rejects_empty_and_malformed_groups():
    with pytest.raises(ValueError, match="state fragments must be lists"):
        parse_fragment_list(json.dumps({"Inventory": {"meta": 5}}),
                            StateVariableFragment, "state")
    with pytest.raises(ValueError, match="state fragments must be lists"):
        parse_fragment_list(json.dumps({"Inventory": 5}), StateVariableFragment, "state")
    with pytest.raises(ValueError, match="state fragments must be a list or keyed object"):
        parse_fragment_list(json.dumps("scalar"), StateVariableFragment, "state")


def test_parse_fragment_list_returns_raw_values_for_dict_model():
    raw = parse_fragment_list(json.dumps([{"name": "unvalidated"}]), dict, "state")
    assert raw == [{"name": "unvalidated"}]


def test_normalize_transition_fragments_maps_type_alias_to_kind():
    normalized = normalize_transition_fragments([{
        "operation_name": "reserve",
        "precondition": {"type": "gt",
                         "left": {"type": "field", "name": "stock"},
                         "right": {"type": "integer", "value": 0}},
        "effects": [{"target": "stock", "set": {"type": "integer", "value": 4}}],
        "frame": ["stock"],
    }])
    precondition = normalized[0]["precondition"]
    assert precondition["kind"] == "gt"
    assert precondition["left"]["kind"] == "field"
    assert normalized[0]["effects"][0]["value"]["kind"] == "integer"
    assert "type" not in precondition


def test_parse_component_fragments_normalizes_empty_optional_strings():
    fragments = parse_component_fragments(json.dumps([
        {"name": "Inventory", "type": "service", "desc": "stock",
         "implements": "", "file": ""}]))
    assert fragments[0].type == "core"
    assert fragments[0].implements is None
    assert fragments[0].file is None


def test_assemble_component_fragments_rejects_duplicates_and_unresolved_references():
    components = [ComponentFragment(name="Inventory", type="core", desc="stock")]
    with pytest.raises(ValueError, match="DUPLICATE_COMPONENT_NAME"):
        assemble_component_fragments(
            [ComponentFragment(name="Inventory", type="core", desc="a"),
             ComponentFragment(name="Inventory", type="core", desc="b")], {}, [])
    with pytest.raises(ValueError, match="UNRESOLVED_COMPONENT_REFERENCE: Ghost"):
        assemble_component_fragments(components, {"Ghost": [_operation()]}, [])
    with pytest.raises(ValueError, match="DUPLICATE_OPERATION_NAME: Inventory"):
        assemble_component_fragments(
            components, {"Inventory": [_operation(), _operation()]}, [])
    with pytest.raises(ValueError, match="UNRESOLVED_COMPONENT_REFERENCE: Ghost"):
        assemble_component_fragments(
            components, {}, [UseCaseStepFragment(component="Ghost", operation="reserve")])
    with pytest.raises(ValueError, match="UNRESOLVED_OPERATION_REFERENCE"):
        assemble_component_fragments(
            components, {"Inventory": [_operation()]},
            [UseCaseStepFragment(component="Inventory", operation="missing")])


def test_assemble_architecture_rejects_unknown_step_component():
    components = [ComponentFragment(name="Inventory", type="core", desc="stock")]
    with pytest.raises(ValueError, match="UNRESOLVED_COMPONENT_REFERENCE: Ghost"):
        assemble_architecture(
            components, {"Inventory": [_operation()]}, {},
            [UseCaseStepFragment(component="Ghost", operation="reserve")], {})


def test_assemble_unified_architecture_builds_validated_staged_shape():
    components = [ComponentFragment(name="Inventory", type="core", desc="stock"),
                  ComponentFragment(name="Checkout", type="orchestrator", desc="flow")]
    unified = assemble_unified_architecture(
        components,
        {"Inventory": [_operation()]},
        {"Inventory": [StateVariableFragment(name="stock", type="int",
                                             bound=(0, 5), initial=5)]},
        [UseCaseStepFragment(component="Inventory", operation="reserve",
                             arguments={"amount": "1"})],
        {"Inventory": [_transition()]},
        name="Shop")
    assert unified.name == "Shop"
    inventory = unified.components[0]
    assert inventory.type == "core"
    assert inventory.state_variables[0].name == "stock"
    assert inventory.transitions[0].operation_name == "reserve"
    assert inventory.operations[0].contract.requires == "amount > 0"
    assert unified.components[1].type == "core"
    assert unified.use_cases[0].steps[0].operation == "reserve"
