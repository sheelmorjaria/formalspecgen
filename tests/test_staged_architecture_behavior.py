import json

import pytest

from pipeline.staged_architecture import (
    ComponentFragment,
    OperationFragment,
    StateVariableFragment,
    UseCaseStepFragment,
    assemble_architecture,
    assemble_component_fragments,
    normalize_component_type,
    normalize_transition_fragments,
    parse_fragment_list,
    parse_operation_fragments,
    StagedOperation,
    StagedComponent,
    UnifiedArchitecture,
    StagedStateVariable,
    TransitionFragment,
    attach_transitions,
    validate_transition,
    parse_json_fragment,
    parse_component_fragments,
)


def _operation(name="reserve"):
    return OperationFragment.model_validate({
        "name": name,
        "params": [{"name": "amount", "type": "int"}],
        "requires": "amount > 0",
        "ensures": "reserved",
        "returns": "boolean",
    })


def test_fragment_parsers_normalize_keyed_shapes_and_contract_lists():
    operations = parse_operation_fragments(json.dumps({"Inventory": [{
        "name": "reserve", "contract": {"requires": ["stock > 0"], "ensures": ["reserved"]},
        "params": []
    }]}))
    assert operations["Inventory"][0].requires == "stock > 0"
    states = parse_fragment_list(json.dumps({"Inventory": {"state_variables": [
        {"name": "stock", "type": "int", "bound": [0, 5], "initial": 5}
    ]}}), StateVariableFragment, "state")
    assert states[0].name == "stock"
    assert normalize_component_type("gateway") == "interface"
    assert normalize_component_type("unknown") == "unknown"


def test_transition_normalization_and_component_assembly_resolve_bindings():
    transition = normalize_transition_fragments([{
        "operation_name": "reserve", "precondition": {"kind": "gt", "left": {"kind": "field", "name": "stock"}, "right": {"kind": "integer", "value": 0}},
        "effects": [{"target": "stock", "set": {"kind": "integer", "value": 4}}],
        "frame": ["stock"],
    }])[0]
    assert transition["effects"][0]["value"]["kind"] == "integer"
    components = [ComponentFragment(name="Inventory", type="core", desc="stock")]
    assembled = assemble_component_fragments(
        components, {"Inventory": [_operation()]},
        [UseCaseStepFragment(component="Inventory", operation="reserve", arguments={"amount": "1"})])
    assert assembled["operations"]["Inventory"][0]["name"] == "reserve"
    with pytest.raises(ValueError, match="MISSING_ARGUMENT_BINDING"):
        assemble_component_fragments(components, {"Inventory": [_operation()]},
                                     [UseCaseStepFragment(component="Inventory", operation="reserve")])


def test_assemble_architecture_maps_layers_and_rejects_unknown_steps():
    components = [ComponentFragment(name="Inventory", type="core", desc="stock")]
    ops = {"Inventory": [_operation()]}
    steps = [UseCaseStepFragment(component="Inventory", operation="reserve", arguments={"amount": "1"})]
    architecture = assemble_architecture(components, ops, {}, steps, {})
    assert architecture.components[0].layer == "entities"
    assert architecture.use_cases[0].steps[0].operation == "reserve"
    with pytest.raises(ValueError, match="UNRESOLVED_OPERATION_REFERENCE"):
        assemble_architecture(components, ops, {},
                              [UseCaseStepFragment(component="Inventory", operation="missing")], {})


def test_staged_models_fail_closed_on_duplicate_and_unbounded_shapes():
    with pytest.raises(ValueError, match="unique"):
        StagedOperation(name="x", params=[{"name": "a", "type": "int"}, {"name": "a", "type": "int"}], contract={"requires": "true", "ensures": "true"})
    with pytest.raises(ValueError, match="UNBOUNDED_STATE_SPACE"):
        StagedStateVariable(name="stock", type="int", bound=None)
    with pytest.raises(ValueError, match="state bounds"):
        StateVariableFragment(name="stock", type="int", bound=(5, 0))
    with pytest.raises(ValueError, match="ADAPTER_REQUIRES_IMPLEMENTS"):
        StagedComponent(name="Adapter", type="adapter")
    with pytest.raises(ValueError, match="EXTERNAL_INTERFACE_REQUIRES_OPERATIONS"):
        StagedComponent(name="Port", type="interface")
    with pytest.raises(ValueError, match="DOMAIN_COMPONENT"):
        StagedComponent(name="Core", type="core", domain="inventory",
                        state_variables=[{"name": "stock", "type": "int", "bound": (0, 5)}])
    with pytest.raises(ValueError, match="DUPLICATE_COMPONENT_NAME"):
        UnifiedArchitecture(name="S", components=[{"name": "X", "type": "core"}, {"name": "X", "type": "core"}])


def test_fragment_repair_and_strict_shape_errors_are_fail_closed():
    repaired = parse_json_fragment('{"name": "x", "type": "int", "bound": [0, 2], "initial": 1}', StateVariableFragment)
    assert repaired.name == "x"
    calls = []
    def repair(prompt):
        calls.append(prompt)
        return '{"name": "x", "type": "int", "bound": [0, 2], "initial": 1}'
    assert parse_json_fragment("not-json", StateVariableFragment, repair_chat=repair).initial == 1
    assert calls
    with pytest.raises(ValueError, match="FRAGMENT_REPAIR_FAILED"):
        parse_json_fragment("not-json", StateVariableFragment, max_attempts=1)
    with pytest.raises(ValueError, match="component fragments must be a JSON list"):
        parse_component_fragments('{}')
    with pytest.raises(ValueError, match="component fragment must be an object"):
        parse_component_fragments('[1]')


def test_transition_validation_and_attachment_reject_frame_state_and_operation_errors():
    transition = TransitionFragment.model_validate({
        "operation_name": "reserve", "precondition": {"kind": "gt", "left": {"kind": "field", "name": "stock"}, "right": {"kind": "integer", "value": 0}},
        "effects": [{"target": "stock", "value": {"kind": "integer", "value": 4}}], "frame": ["stock"]})
    validate_transition(transition, {"stock"})
    assert attach_transitions("Inventory", {"reserve"}, [transition]) == [transition]
    with pytest.raises(ValueError, match="FRAME_CONSISTENCY_ERROR"):
        validate_transition(transition.model_copy(update={"frame": ["other"]}), {"stock"})
    with pytest.raises(ValueError, match="UNDECLARED_STATE_REFERENCE"):
        validate_transition(transition, {"other"})
    with pytest.raises(ValueError, match="UNDECLARED_OPERATION_TRANSITION"):
        attach_transitions("Inventory", {"release"}, [transition])
    with pytest.raises(ValueError, match="DUPLICATE_OPERATION_TRANSITION"):
        attach_transitions("Inventory", {"reserve"}, [transition, transition])
