# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Count-bound regressions; no provider or external verifier is invoked."""
from collections import deque
from functools import partial
import json

import pytest
import yaml

from pipeline.domain_v2 import DomainSpecV2
from pipeline import domain_v2_model as model
from pipeline import domain_v2_validation as validation


def candidate(*, count=1, enabled=True, boolean=False, lock=False):
    operations = [{"name": f"step{i}", "return_type": "boolean" if boolean else "void",
        "failure_semantics": "false_and_stutter" if boolean else "unavailable",
        "guards": [{"id": "enabled", "expression": {"kind": "boolean", "value": enabled}}],
        "effects": [], "frame": []} for i in range(count)]
    value = {"domain_name": "Bounded", "module_name": "bounded",
        "actors": 2 if boolean or lock else 1,
        "state_variables": [{"kind": "int", "name": "lock" if lock else "x",
                             "bound": [0, 2], "initial": 0}],
        "operations": operations, "tlc_invariants": [{"id": "TrueInvariant",
            "expression": {"kind": "boolean", "value": True}}]}
    if lock:
        value["concurrency"] = {"mode": "lock_protocol", "lock_variable": "lock",
            "lock_states": ["FREE", "A", "B"], "unlocked_value": 0,
            "actor_lock_values": [1, 2],
            "linearization_points": {op["name"]: "effect_commit" for op in operations}}
    return DomainSpecV2.model_validate(value)


@pytest.mark.parametrize("name", ["max_states", "max_transitions", "max_work_items"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2", None])
def test_invalid_limits_fail_before_evaluation(monkeypatch, name, value):
    def forbidden(*_):
        pytest.fail("invalid limits reached model evaluation")
    monkeypatch.setattr(model, "_check_bounds", forbidden)
    with pytest.raises(ValueError, match=f"{name} must be a positive integer"):
        model.validate_transitions_and_invariants(candidate(), **{name: value})


def test_duplicate_successors_never_expand_queue_and_edges_still_count(monkeypatch):
    queues = []
    class TrackingDeque(deque):
        def __init__(self):
            super().__init__()
            self.appends = self.peak = 0
            queues.append(self)
        def append(self, value):
            super().append(value)
            self.appends += 1
            self.peak = max(self.peak, len(self))
    monkeypatch.setattr(model, "deque", TrackingDeque)
    assert model.validate_transitions_and_invariants(candidate(count=256),
        max_states=1, max_transitions=256, max_work_items=512) == (1, 256)
    assert queues[0].appends == queues[0].peak == 1
    with pytest.raises(model.UnsupportedV2Boundary, match="transitions exceed maximum 255"):
        model.validate_transitions_and_invariants(candidate(count=256), max_transitions=255)


@pytest.mark.parametrize("enabled", [True, False])
def test_actor_results_keep_exact_counts_and_enforce_state_limit(enabled):
    spec = candidate(boolean=True, enabled=enabled)
    assert model.validate_transitions_and_invariants(spec,
        max_states=4, max_transitions=8, max_work_items=12) == (4, 8)
    with pytest.raises(model.UnsupportedV2Boundary, match="states exceed maximum 3"):
        model.validate_transitions_and_invariants(spec, max_states=3)
    with pytest.raises(model.UnsupportedV2Boundary, match="transitions exceed maximum 7"):
        model.validate_transitions_and_invariants(spec, max_transitions=7)
    with pytest.raises(model.UnsupportedV2Boundary, match="work items exceed maximum 11"):
        model.validate_transitions_and_invariants(spec, max_work_items=11)


def test_disabled_actions_consume_work_before_guard_evaluation(monkeypatch):
    calls = []
    original = model.guards_hold
    def counted(*args):
        calls.append(args[0].name)
        return original(*args)
    monkeypatch.setattr(model, "guards_hold", counted)
    with pytest.raises(model.UnsupportedV2Boundary, match="work items exceed maximum 3"):
        model.validate_transitions_and_invariants(candidate(count=20, enabled=False), max_work_items=3)
    assert calls == ["step0", "step1", "step2"]
    with pytest.raises(model.V2ValidationError, match="no enabled transition"):
        model.validate_transitions_and_invariants(candidate(count=3, enabled=False), max_work_items=3)


def test_state_limit_is_enforced_before_retaining_new_successor(monkeypatch):
    captured = []
    original = model._BoundedFrontier
    class ObservedFrontier(original):
        def __init__(self, *args):
            super().__init__(*args)
            captured.append(self)
    monkeypatch.setattr(model, "_BoundedFrontier", ObservedFrontier)
    with pytest.raises(model.UnsupportedV2Boundary, match="states exceed maximum 1"):
        model.validate_transitions_and_invariants(candidate(boolean=True), max_states=1)
    assert len(captured[0].discovered) == 1
    assert not captured[0].queue


def test_lock_history_preserves_state_and_transition_counts():
    assert model.validate_transitions_and_invariants(candidate(lock=True),
        max_states=21, max_transitions=38) == (21, 38)
    with pytest.raises(model.UnsupportedV2Boundary, match="states exceed maximum 20"):
        model.validate_transitions_and_invariants(candidate(lock=True), max_states=20)


@pytest.mark.parametrize("limit", [1, 3, 10, 37])
def test_lock_history_charges_all_transition_phases(limit):
    with pytest.raises(model.UnsupportedV2Boundary, match=f"transitions exceed maximum {limit}"):
        model.validate_transitions_and_invariants(candidate(lock=True), max_transitions=limit)


@pytest.mark.parametrize("enabled", [False, True])
def test_lock_actor_and_idle_operation_attempts_are_work_bounded(enabled):
    with pytest.raises(model.UnsupportedV2Boundary, match="work items exceed maximum 3"):
        model.validate_transitions_and_invariants(candidate(lock=True, enabled=enabled), max_work_items=3)


@pytest.mark.parametrize("limits", [
    {"max_states": 1}, {"max_transitions": 1}, {"max_work_items": 1}])
def test_exhaustion_records_failure_and_never_reaches_tlc(tmp_path, monkeypatch, limits):
    source = tmp_path / "candidate.yaml"
    source.write_text(yaml.safe_dump(candidate(boolean=True).model_dump(mode="json")))
    failure, success = tmp_path / "failed.json", tmp_path / "validated.json"
    monkeypatch.setattr(validation, "validate_transitions_and_invariants",
        partial(model.validate_transitions_and_invariants, **limits))
    def forbidden(*_args, **_kwargs):
        pytest.fail("exhausted traversal reached rendering or external execution")
    monkeypatch.setattr(validation, "render_v2_tla", forbidden)
    with pytest.raises(model.UnsupportedV2Boundary):
        validation.validate_v2_candidate(source, success, failure_path=failure,
                                         tlc_jar="unused.jar", runner=forbidden)
    assert not success.exists()
    result = json.loads(failure.read_text())
    assert result["validation_status"] == "VALIDATION_FAILED"
    assert result["failed_gate"] == "bounded_traversal"
    assert result["tool_provenance"] == {}
