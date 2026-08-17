# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M20: the pre-TLC static deadlock net.

A value that can be entered (initial or literal-written) but that no
operation's guards provably admit is the missing recycle()/reset() class of
review error — the exact bug TLC caught in the Tomcat port. The static gate
catches it in milliseconds; terminal_states marks legitimate end states.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pipeline.domain_v2_model import static_deadlock_findings
from pipeline.domain_v2_promotion import load_candidate
from pipeline.domain_v2_validation import validate_v2_candidate


def _spec(operations, terminal_states=None, field="phase", bound=(-1, 7)):
    return {
        "schema_version": 2, "review_status": "unreviewed",
        "domain_name": "PhaseMachine", "module_name": "phase_machine",
        "actors": 1,
        "state_variables": [
            {"kind": "int", "name": field, "bound": list(bound), "initial": 0,
             **({"terminal_states": terminal_states} if terminal_states else {})}],
        "operations": operations,
        "tlc_invariants": [{"id": "inv1", "expression": {
            "kind": "and",
            "left": {"kind": "gte",
                     "left": {"kind": "field", "name": field},
                     "right": {"kind": "integer", "value": bound[0]}},
            "right": {"kind": "lte",
                      "left": {"kind": "field", "name": field},
                      "right": {"kind": "integer", "value": bound[1]}}}}],
    }


def _op(name, guard_value, effect_value, field="phase"):
    return {
        "name": name, "return_type": "void", "failure_semantics": "unavailable",
        "guards": [{"id": f"g_{name}", "expression": {
            "kind": "eq",
            "left": {"kind": "field", "name": field},
            "right": {"kind": "integer", "value": guard_value}}}],
        "effects": [{"id": f"e_{name}", "target": field,
                     "value": {"kind": "integer", "value": effect_value}}],
        "frame": [field],
    }


TOMCAT_WITHOUT_RECYCLE = _spec([
    _op("advance_0", 0, 1),
    _op("advance_1", 1, 2),
    _op("eof_abort", 2, -1),       # enters the EOF state...
    # ...and nothing ever leaves -1: the Tomcat review bug
])


def test_eof_value_without_reset_is_deadlock_risk():
    from pipeline.domain_v2 import DomainSpecV2
    spec = DomainSpecV2.model_validate(TOMCAT_WITHOUT_RECYCLE)
    findings = static_deadlock_findings(spec)
    assert any("phase == -1" in f and "DEADLOCK_RISK" in f and "recycle" in f
               for f in findings), findings


def test_recycle_transition_clears_the_risk():
    from pipeline.domain_v2 import DomainSpecV2
    with_recycle = dict(TOMCAT_WITHOUT_RECYCLE)
    with_recycle["operations"] = TOMCAT_WITHOUT_RECYCLE["operations"] + [
        _op("recycle", -1, 0)]
    spec = DomainSpecV2.model_validate(with_recycle)
    assert static_deadlock_findings(spec) == []


def test_terminal_states_marking_exempts_legitimate_end_states():
    from pipeline.domain_v2 import DomainSpecV2
    marked = json.loads(json.dumps(TOMCAT_WITHOUT_RECYCLE))
    marked["state_variables"][0]["terminal_states"] = [-1]
    spec = DomainSpecV2.model_validate(marked)
    assert static_deadlock_findings(spec) == []


def test_conservative_on_undecidable_guards_and_unwritten_values():
    """A guard conditioning on another (unknown) field admits the value, and
    arithmetic effect targets are not claimed as written values — the gate
    only fires on what it can prove."""
    from pipeline.domain_v2 import DomainSpecV2
    payload = _spec([
        _op("advance_0", 0, 2),        # the initial value must have an exit
        {"name": "guarded_exit", "return_type": "void",
         "failure_semantics": "unavailable",
         "guards": [
             {"id": "g1", "expression": {"kind": "eq",
               "left": {"kind": "field", "name": "phase"},
               "right": {"kind": "integer", "value": -1}}},
             {"id": "g2", "expression": {"kind": "eq",
               "left": {"kind": "field", "name": "other"},
               "right": {"kind": "boolean", "value": True}}}],
         "effects": [{"id": "e1", "target": "phase",
                      "value": {"kind": "integer", "value": 0}}],
         "frame": ["phase"]},
        {"name": "counter", "return_type": "void",
         "failure_semantics": "unavailable",
         "guards": [{"id": "g3", "expression": {"kind": "eq",
               "left": {"kind": "field", "name": "phase"},
               "right": {"kind": "integer", "value": 2}}}],
         "effects": [{"id": "e2", "target": "phase",
                      "value": {"kind": "add",
                                "left": {"kind": "field", "name": "phase"},
                                "right": {"kind": "integer", "value": 1}}}],
         "frame": ["phase"]},
    ])
    payload["state_variables"].append(
        {"kind": "bool", "name": "other", "initial": False})
    spec = DomainSpecV2.model_validate(payload)
    # the eof value's exit is conditioned on `other` (undecidable) -> admitted
    assert static_deadlock_findings(spec) == []


def _candidate_file(tmp_path, payload, name="phase_machine"):
    path = tmp_path / f"{name}.v2.yaml"
    import yaml
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_validation_fails_closed_before_tlc_on_deadlock(tmp_path):
    candidate = _candidate_file(tmp_path, TOMCAT_WITHOUT_RECYCLE)
    runner = MagicMock()
    with pytest.raises(RuntimeError, match="DEADLOCK_RISK"):
        validate_v2_candidate(
            candidate, tmp_path / "ok.json", failure_path=tmp_path / "fail.json",
            tlc_jar="tla2tools.jar", runner=runner)
    runner.assert_not_called()          # TLC never paid for a static catch
    failure = json.loads((tmp_path / "fail.json").read_text(encoding="utf-8"))
    assert failure["failed_gate"] == "static_deadlock"
    assert "phase == -1" in failure["diagnostic"]


def test_validation_passes_static_gate_with_terminal_marking(tmp_path):
    marked = json.loads(json.dumps(TOMCAT_WITHOUT_RECYCLE))
    marked["state_variables"][0]["terminal_states"] = [-1]
    candidate = _candidate_file(tmp_path, marked)

    class FakeResult:
        status = "VERIFIED"
        exit_status = 0
        output = "TLC2 Version 2.19"
        diagnostic = ""

    class FakeProvenance:
        pass

    def fake_provenance(*_args, **_kwargs):
        return {"version": "2.19 of 08 August 2024", "command": ["java"],
                "status": "OK", "exit_status": 0}

    import pipeline.domain_v2_validation as validation
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(validation, "require_tlc_provenance", lambda p: p)
        patcher.setattr(validation, "get_tlc_provenance", fake_provenance)
        patcher.setattr(validation, "run_tlc_artifacts",
                        lambda *a, **k: {"status": "VERIFIED", "exit_status": 0})
        evidence = validate_v2_candidate(
            candidate, tmp_path / "ok.json", failure_path=tmp_path / "fail.json",
            tlc_jar="tla2tools.jar")
    assert evidence.reachable_state_count is not None


def test_repo_candidates_pass_the_static_gate():
    """No false positives against the repo's own registered candidates."""
    root = Path(__file__).resolve().parents[2]
    candidates = sorted((root / "domains" / "candidates").glob("*.v2.yaml"))
    assert candidates, "registered V2 candidates must exist"
    for path in candidates:
        try:
            spec = load_candidate(path)
        except Exception:
            continue          # deliberately-invalid schema fixtures in the tree
        findings = static_deadlock_findings(spec)
        assert findings == [], f"{path.name}: {findings}"


def test_three_valued_evaluator_branches():
    """Short-circuits and unknown propagation over the typed AST."""
    from pipeline.domain_v2 import (
        BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr,
    )
    from pipeline.domain_v2_model import UNKNOWN, _evaluate3, V2ValidationError

    def binary(kind, left, right):
        return BinaryExpr(kind=kind, left=left, right=right)

    def field(name):
        return FieldExpr(kind="field", name=name)

    def integer(value):
        return IntegerExpr(kind="integer", value=value)

    def boolean(value):
        return BooleanExpr(kind="boolean", value=value)

    env = {"known": 3, "mystery": UNKNOWN}
    # arithmetic with an unknown operand stays unknown
    assert isinstance(_evaluate3(
        binary("add", field("mystery"), integer(1)), env), type(UNKNOWN))
    assert _evaluate3(binary("sub", field("known"), integer(2)), env) == 1
    assert _evaluate3(binary("add", field("known"), integer(2)), env) == 5
    # boolean short-circuits fire even with unknowns present
    assert _evaluate3(binary("and", boolean(False), field("mystery")), env) is False
    assert _evaluate3(binary("or", boolean(True), field("mystery")), env) is True
    assert _evaluate3(binary("implies", boolean(False), field("mystery")), env) is True
    assert _evaluate3(binary("implies", field("mystery"), boolean(True)), env) is True
    # undecided when neither side decides
    assert isinstance(_evaluate3(
        binary("and", field("mystery"), field("mystery")), env), type(UNKNOWN))
    # not over unknown stays unknown; unknown fields read as unknown
    assert isinstance(_evaluate3(
        NotExpr(kind="not", expression=field("mystery")), env), type(UNKNOWN))
    assert isinstance(_evaluate3(field("absent"), env), type(UNKNOWN))
    # OldExpr evaluates through to its inner expression
    from pipeline.domain_v2 import OldExpr
    assert _evaluate3(OldExpr(kind="old", expression=field("known")), env) == 3
    # unsupported nodes fail closed
    with pytest.raises(V2ValidationError):
        _evaluate3(object(), env)
