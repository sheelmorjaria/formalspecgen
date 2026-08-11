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
    op={"name":"stay","return_type":"void","failure_semantics":"unavailable",
        "guards":[],"effects":[],"frame":[]}
    variables=[{"kind":"int","name":f"v{i}","bound":[0,10],"initial":0}
               for i in range(5)]
    with pytest.raises(UnsupportedV2Boundary):
        validate_transitions_and_invariants(spec_with(op,variables=variables))


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
    assert validate_transitions_and_invariants(
        spec_with(disabled,variables=variables)) == (1,0)
