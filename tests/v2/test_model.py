# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import pytest

from pipeline.domain_v2 import DomainSpecV2
from pipeline.domain_v2_model import (
    UnsupportedV2Boundary, V2ValidationError, apply_effects, evaluate_expression,
    state_space_upper_bound, validate_transitions_and_invariants,
)


def spec_with(operation, *, actors=1, variables=None, invariant=None):
    variables = variables or [
        {"kind":"int","name":"x","bound":[0,2],"initial":1},
        {"kind":"int","name":"y","bound":[0,2],"initial":2}]
    invariant = invariant or {"id":"NonNegative","expression":{
        "kind":"gte","left":{"kind":"field","name":variables[0]["name"]},
        "right":{"kind":"integer","value":0}}}
    return DomainSpecV2.model_validate({"schema_version":2,"domain_name":"TestDomain",
        "module_name":"test_domain","actors":actors,"state_variables":variables,
        "operations":[operation],"tlc_invariants":[invariant]})


def test_state_space_upper_bound_includes_per_actor_last_results():
    op={"name":"move","return_type":"boolean","failure_semantics":"false_and_stutter",
        "guards":[],"effects":[],"frame":[]}
    variables=[{"kind":"int","name":"floor","bound":[0,4],"initial":0},
      {"kind":"int","name":"door","bound":[0,1],"initial":0},
      {"kind":"int","name":"motion","bound":[0,2],"initial":0}]
    assert state_space_upper_bound(spec_with(op,actors=2,variables=variables)) == 270


def test_oversized_state_space_fails_closed():
    # Five independently incrementable counters: the reachable set itself
    # (11^5 = 161,051) exceeds the exploration cap, not just the estimate.
    operations=[{"name":f"inc{i}","return_type":"void","failure_semantics":"unavailable",
                 "guards":[{"id":"g1","expression":{
                     "kind":"lt","left":{"kind":"field","name":f"v{i}"},
                     "right":{"kind":"integer","value":10}}}],
                 "effects":[{"id":"e1","target":f"v{i}","value":{
                     "kind":"add","left":{"kind":"field","name":f"v{i}"},
                     "right":{"kind":"integer","value":1}}}],
                 "frame":[f"v{i}"]} for i in range(5)]
    variables=[{"kind":"int","name":f"v{i}","bound":[0,10],"initial":0}
               for i in range(5)]
    spec = DomainSpecV2.model_validate({"schema_version":2,"domain_name":"BigDomain",
        "module_name":"big_domain","actors":1,"state_variables":variables,
        "operations":operations,
        "tlc_invariants":[{"id":"NonNegative","expression":{
            "kind":"gte","left":{"kind":"field","name":"v0"},
            "right":{"kind":"integer","value":0}}}]})
    with pytest.raises(UnsupportedV2Boundary):
        validate_transitions_and_invariants(spec)


def test_wide_bounds_with_small_reachable_set_validate():
    """Hardware capacities produce wide bounds but sparse reachable sets: a
    counter set to a literal then decremented explores O(bound) states along
    one axis, not the product. The cap must bind on exploration, not on the
    worst-case estimate."""
    operation={"name":"consume","return_type":"void","failure_semantics":"unavailable",
               "guards":[{"id":"g1","expression":{
                   "kind":"gt","left":{"kind":"field","name":"pending"},
                   "right":{"kind":"integer","value":0}}}],
               "effects":[{"id":"e1","target":"pending","value":{
                   "kind":"sub","left":{"kind":"field","name":"pending"},
                   "right":{"kind":"integer","value":1}}}],
               "frame":["pending"]}
    variables=[{"kind":"int","name":"pending","bound":[0,7372],"initial":7372},
               {"kind":"int","name":"tag","bound":[0,7372],"initial":0}]
    states, transitions = validate_transitions_and_invariants(
        spec_with(operation, variables=variables))
    assert states == 7373          # one axis, not 7373 * 7373
    assert transitions == 7372


def test_effects_are_evaluated_simultaneously_swap_regression():
    op={"name":"swap","return_type":"void","failure_semantics":"unavailable","guards":[],
      "effects":[{"id":"x_from_y","target":"x","value":{"kind":"field","name":"y"}},
                 {"id":"y_from_x","target":"y","value":{"kind":"field","name":"x"}}],
      "frame":["x","y"]}
    parsed=spec_with(op).operations[0]
    assert apply_effects(parsed,{"x":1,"y":2}) == {"x":2,"y":1}


def test_unsafe_upper_floor_guard_is_found_by_reachability():
    op={"name":"moveUp","return_type":"void","failure_semantics":"unavailable",
      "guards":[{"id":"bad_guard","expression":{"kind":"lt","left":{"kind":"field","name":"floor"},"right":{"kind":"integer","value":5}}}],
      "effects":[{"id":"increment","target":"floor","value":{"kind":"add","left":{"kind":"old","expression":{"kind":"field","name":"floor"}},"right":{"kind":"integer","value":1}}}],"frame":["floor"]}
    variables=[{"kind":"int","name":"floor","bound":[0,4],"initial":0}]
    with pytest.raises(V2ValidationError,match="out-of-bounds"):
        validate_transitions_and_invariants(spec_with(op,variables=variables))


def test_false_and_stutter_changes_only_per_actor_result():
    op={"name":"tryMove","return_type":"boolean","failure_semantics":"false_and_stutter",
      "guards":[{"id":"never","expression":{"kind":"boolean","value":False}}],
      "effects":[],"frame":[]}
    variables=[{"kind":"int","name":"floor","bound":[0,4],"initial":0}]
    states, transitions=validate_transitions_and_invariants(
        spec_with(op,actors=2,variables=variables))
    assert states == 4  # none/none, false/none, none/false, false/false
    assert transitions == 8


def test_evaluator_fails_closed_on_unknown_fields_and_nodes():
    from pipeline.domain_v2 import FieldExpr
    with pytest.raises(V2ValidationError, match="unknown state field"):
        evaluate_expression(FieldExpr(name="missing"), {})
    with pytest.raises(V2ValidationError, match="unsupported expression"):
        evaluate_expression(object(), {})


def test_evaluator_supports_typed_logical_negation():
    from pipeline.domain_v2 import NotExpr, BooleanExpr
    assert evaluate_expression(NotExpr(expression=BooleanExpr(value=False)), {}) is True
    assert evaluate_expression(NotExpr(expression=NotExpr(
        expression=BooleanExpr(value=True))), {}) is True


def test_schema_rejects_mixed_boolean_integer_expressions_and_effects():
    variables = [{"kind": "bool", "name": "bit", "initial": False}]
    mixed_guard = {"name": "step", "return_type": "void",
        "failure_semantics": "unavailable", "guards": [{"id": "bad", "expression": {
            "kind": "eq", "left": {"kind": "field", "name": "bit"},
            "right": {"kind": "integer", "value": -1}}}],
        "effects": [], "frame": []}
    with pytest.raises(ValueError, match="same scalar type"):
        spec_with(mixed_guard, variables=variables,
                  invariant={"id": "Typed", "expression": {
                      "kind": "boolean", "value": True}})

    mixed_effect = {"name": "step", "return_type": "void",
        "failure_semantics": "unavailable", "guards": [],
        "effects": [{"id": "bad", "target": "bit",
                     "value": {"kind": "integer", "value": 1}}], "frame": ["bit"]}
    with pytest.raises(ValueError, match="does not match its target"):
        spec_with(mixed_effect, variables=variables,
                  invariant={"id": "Typed", "expression": {
                      "kind": "boolean", "value": True}})


def test_expression_type_checker_rejects_wrong_unary_arithmetic_and_logic_sorts():
    from pipeline.domain_v2 import (
        BinaryExpr, BooleanExpr, IntegerExpr, NotExpr, _expression_type,
    )
    with pytest.raises(ValueError, match="boolean operand"):
        _expression_type(NotExpr(expression=IntegerExpr(value=1)), {})
    with pytest.raises(ValueError, match="integer operands"):
        _expression_type(BinaryExpr(kind="add", left=BooleanExpr(value=True),
                                    right=IntegerExpr(value=1)), {})
    with pytest.raises(ValueError, match="boolean operands"):
        _expression_type(BinaryExpr(kind="and", left=IntegerExpr(value=1),
                                    right=BooleanExpr(value=True)), {})


def test_schema_requires_boolean_guards_exception_triggers_and_invariants():
    variables = [{"kind": "int", "name": "x", "bound": [0, 2], "initial": 0}]
    integer = {"kind": "integer", "value": 1}
    bad_guard = {"name": "step", "return_type": "void",
        "failure_semantics": "unavailable",
        "guards": [{"id": "bad", "expression": integer}],
        "effects": [], "frame": []}
    with pytest.raises(ValueError, match="guard bad must be boolean"):
        spec_with(bad_guard, variables=variables,
                  invariant={"id": "Typed", "expression": {
                      "kind": "boolean", "value": True}})

    bad_trigger = {"name": "step", "return_type": "void",
        "failure_semantics": "exception", "exception_type": "Failure",
        "exception_trigger": integer, "guards": [], "effects": [], "frame": []}
    with pytest.raises(ValueError, match="exception trigger must be boolean"):
        spec_with(bad_trigger, variables=variables,
                  invariant={"id": "Typed", "expression": {
                      "kind": "boolean", "value": True}})

    valid = {"name": "step", "return_type": "void",
             "failure_semantics": "unavailable", "guards": [],
             "effects": [], "frame": []}
    with pytest.raises(ValueError, match="invariant Typed must be boolean"):
        spec_with(valid, variables=variables,
                  invariant={"id": "Typed", "expression": integer})


def test_schema_accepts_valid_lock_metadata_and_rejects_unbound_or_single_actor_lock():
    operation = {"name": "step", "return_type": "void",
                 "failure_semantics": "unavailable", "guards": [],
                 "effects": [], "frame": []}
    variables = [{"kind": "int", "name": "account_lock",
                  "bound": [0, 2], "initial": 0}]
    value = spec_with(operation, actors=2, variables=variables).model_dump(mode="json")
    value["concurrency"] = {"mode": "lock_protocol",
                            "lock_variable": "account_lock",
                            "lock_states": ["UNLOCKED", "LOCKED_BY_A", "LOCKED_BY_B"]}
    parsed = DomainSpecV2.model_validate(value)
    assert parsed.concurrency.mode == "lock_protocol"
    assert parsed.concurrency.lock_variable == "account_lock"

    value["concurrency"]["lock_variable"] = "missing"
    with pytest.raises(ValueError, match="must be declared state"):
        DomainSpecV2.model_validate(value)
    value["concurrency"]["lock_variable"] = "account_lock"
    value["actors"] = 1
    with pytest.raises(ValueError, match="at least two actors"):
        DomainSpecV2.model_validate(value)
    value["actors"] = 2
    value["concurrency"]["lock_states"] = ["UNLOCKED", "UNLOCKED"]
    with pytest.raises(ValueError, match="lock states must be unique"):
        DomainSpecV2.model_validate(value)


def test_bounded_traverser_explores_complete_lock_history_phases():
    operation = {"name": "read", "return_type": "void",
                 "failure_semantics": "unavailable", "guards": [],
                 "effects": [], "frame": []}
    variables = [{"kind": "int", "name": "lock",
                  "bound": [0, 2], "initial": 0}]
    value = spec_with(operation, actors=2, variables=variables).model_dump(mode="json")
    value["concurrency"] = {"mode": "lock_protocol", "lock_variable": "lock",
        "lock_states": ["UNLOCKED", "LOCKED_A", "LOCKED_B"], "unlocked_value": 0,
        "actor_lock_values": [1, 2],
        "linearization_points": {"read": "effect_commit"}}
    spec = DomainSpecV2.model_validate(value)
    states, transitions = validate_transitions_and_invariants(spec)
    assert (states, transitions) == (21, 38)
    assert state_space_upper_bound(spec) == 75


def test_lock_history_false_guard_rejects_and_responds_without_domain_effect():
    operation = {"name": "blocked", "return_type": "void",
                 "failure_semantics": "unavailable", "guards": [{"id": "never",
                     "expression": {"kind": "boolean", "value": False}}],
                 "effects": [], "frame": []}
    variables = [{"kind": "int", "name": "lock", "bound": [0, 2], "initial": 0}]
    value = spec_with(operation, actors=2, variables=variables).model_dump(mode="json")
    value["concurrency"] = {"mode": "lock_protocol", "lock_variable": "lock",
        "lock_states": ["UNLOCKED", "LOCKED_A", "LOCKED_B"], "unlocked_value": 0,
        "actor_lock_values": [1, 2],
        "linearization_points": {"blocked": "effect_commit"}}
    states, transitions = validate_transitions_and_invariants(
        DomainSpecV2.model_validate(value))
    assert states > 1 and transitions > 0


@pytest.mark.parametrize("mutation, message", [
    ("boolean_lock", "bounded integer state"),
    ("partial", "must be complete"),
    ("state_names", "unlocked plus every actor"),
    ("owner_count", "unique and total"),
    ("owner_duplicate", "unique and total"),
    ("unlocked_collision", "must differ"),
    ("locked_initial", "initialize to the unlocked"),
    ("owner_out_of_bounds", "within lock bounds"),
    ("missing_linearization", "cover every operation"),
    ("boolean_operation", "void/unavailable"),
    ("mutates_lock", "cannot directly mutate"),
    ("references_lock", "cannot reference protocol lock"),
])
def test_explicit_lock_protocol_metadata_fails_closed_at_each_boundary(mutation, message):
    import copy
    operation = {"name": "read", "return_type": "void",
                 "failure_semantics": "unavailable", "guards": [],
                 "effects": [], "frame": []}
    variables = [{"kind": "int", "name": "lock", "bound": [0, 2], "initial": 0}]
    value = spec_with(operation, actors=2, variables=variables).model_dump(mode="json")
    value["concurrency"] = {"mode": "lock_protocol", "lock_variable": "lock",
        "lock_states": ["UNLOCKED", "LOCKED_A", "LOCKED_B"], "unlocked_value": 0,
        "actor_lock_values": [1, 2],
        "linearization_points": {"read": "effect_commit"}}
    value = copy.deepcopy(value)
    if mutation == "boolean_lock":
        value["state_variables"] = [{"kind": "bool", "name": "lock", "initial": False}]
    elif mutation == "partial":
        value["concurrency"]["actor_lock_values"] = None
    elif mutation == "state_names":
        value["concurrency"]["lock_states"] = ["UNLOCKED", "LOCKED"]
    elif mutation == "owner_count":
        value["concurrency"]["actor_lock_values"] = [1]
    elif mutation == "owner_duplicate":
        value["concurrency"]["actor_lock_values"] = [1, 1]
    elif mutation == "unlocked_collision":
        value["concurrency"]["unlocked_value"] = 1
    elif mutation == "locked_initial":
        value["state_variables"][0]["initial"] = 1
    elif mutation == "owner_out_of_bounds":
        value["concurrency"]["actor_lock_values"] = [1, 3]
    elif mutation == "missing_linearization":
        value["concurrency"]["linearization_points"] = {}
    elif mutation == "boolean_operation":
        value["operations"][0].update(
            return_type="boolean", failure_semantics="false_and_stutter")
    elif mutation == "mutates_lock":
        value["operations"][0].update(
            effects=[{"id": "set", "target": "lock",
                      "value": {"kind": "integer", "value": 1}}], frame=["lock"])
    elif mutation == "references_lock":
        value["operations"][0]["guards"] = [{"id": "free", "expression": {
            "kind": "eq", "left": {"kind": "field", "name": "lock"},
            "right": {"kind": "integer", "value": 0}}}]
    with pytest.raises(ValueError, match=message):
        DomainSpecV2.model_validate(value)


def test_initial_invariant_failure_is_reported():
    op={"name":"stay","return_type":"void","failure_semantics":"unavailable",
        "guards":[],"effects":[],"frame":[]}
    variables=[{"kind":"int","name":"floor","bound":[0,4],"initial":0}]
    invariant={"id":"MustBePositive","expression":{"kind":"gt",
        "left":{"kind":"field","name":"floor"},"right":{"kind":"integer","value":0}}}
    with pytest.raises(V2ValidationError,match="violates invariant"):
        validate_transitions_and_invariants(spec_with(op,variables=variables,invariant=invariant))


def test_boolean_success_records_true_and_disabled_void_action_is_unavailable():
    success={"name":"tryMove","return_type":"boolean","failure_semantics":"false_and_stutter",
      "guards":[{"id":"enabled","expression":{"kind":"boolean","value":True}}],
      "effects":[],"frame":[]}
    variables=[{"kind":"int","name":"floor","bound":[0,1],"initial":0}]
    states, transitions=validate_transitions_and_invariants(
        spec_with(success,actors=2,variables=variables))
    assert states == 4 and transitions == 8
    disabled={"name":"disabled","return_type":"void","failure_semantics":"unavailable",
      "guards":[{"id":"never","expression":{"kind":"boolean","value":False}}],
      "effects":[],"frame":[]}
    with pytest.raises(V2ValidationError, match="initial state has no enabled transition"):
        validate_transitions_and_invariants(spec_with(disabled,variables=variables))
