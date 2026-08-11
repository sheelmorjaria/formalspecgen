# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
import subprocess
from unittest.mock import patch

import pytest
import yaml

from pipeline.domain_v2_promotion import candidate_sha256, load_candidate
from pipeline.domain_v2_validation import validate_domain, validate_v2_candidate


def candidate_value():
    return {
        "schema_version": 2, "review_status": "unreviewed",
        "domain_name": "CounterDomain", "module_name": "counter_domain", "actors": 1,
        "state_variables": [{"kind": "int", "name": "count", "bound": [0, 2],
                             "initial": 0}],
        "operations": [{"name": "Increment", "return_type": "void",
            "failure_semantics": "unavailable",
            "guards": [{"id": "below_max", "expression": {"kind": "lt",
                "left": {"kind": "field", "name": "count"},
                "right": {"kind": "integer", "value": 2}}}],
            "effects": [{"id": "increment", "target": "count", "value": {
                "kind": "add", "left": {"kind": "old", "expression": {
                    "kind": "field", "name": "count"}},
                "right": {"kind": "integer", "value": 1}}}], "frame": ["count"]}],
        "tlc_invariants": [{"id": "CountNonNegative", "expression": {"kind": "gte",
            "left": {"kind": "field", "name": "count"},
            "right": {"kind": "integer", "value": 0}}}],
    }


def write_candidate(path):
    path.write_text(yaml.safe_dump(candidate_value(), sort_keys=False), encoding="utf-8")


def successful_runner(command, **_kwargs):
    if command[-1] == "-help":
        return subprocess.CompletedProcess(command, 0, "TLC2 Version 2.19\n", "")
    return subprocess.CompletedProcess(command, 0, "Model checking completed", "")


def test_validation_measures_runs_tlc_and_publishes_bound_envelope(tmp_path):
    candidate = tmp_path / "counter.v2.yaml"; write_candidate(candidate)
    validation = tmp_path / "counter.validation.json"
    failure = tmp_path / "counter.validation_failed.json"
    evidence = validate_v2_candidate(
        candidate, validation, failure_path=failure, tlc_jar="tlc.jar",
        java="java", runner=successful_runner)
    envelope = json.loads(validation.read_text(encoding="utf-8"))
    assert evidence.reachable_state_count == 3
    assert evidence.reachable_transition_count == 2
    assert evidence.candidate_sha256 == candidate_sha256(load_candidate(candidate))
    assert envelope["evidence"]["tlc_exit_status"] == 0
    assert envelope["evidence"]["tools"]["tlc"]["version"] == "2.19"
    assert not failure.exists()


def test_tlc_failure_is_retained_separately_and_not_published_as_validated(tmp_path):
    candidate = tmp_path / "counter.v2.yaml"; write_candidate(candidate)
    validation = tmp_path / "counter.validation.json"
    failure = tmp_path / "counter.validation_failed.json"
    def runner(command, **_kwargs):
        if command[-1] == "-help":
            return subprocess.CompletedProcess(command, 0, "TLC2 Version 2.19\n", "")
        return subprocess.CompletedProcess(command, 12, "", "counterexample")
    with pytest.raises(RuntimeError, match="TLC did not verify"):
        validate_v2_candidate(candidate, validation, failure_path=failure,
                              tlc_jar="tlc.jar", runner=runner)
    failed = json.loads(failure.read_text(encoding="utf-8"))
    assert failed["failed_gate"] == "tlc"
    assert not validation.exists()


def test_renderer_failure_is_published_with_the_failing_gate(tmp_path):
    value = candidate_value()
    value["operations"][0].update(
        return_type="boolean", failure_semantics="exception",
        exception_type="IllegalStateException",
        exception_trigger={"kind": "boolean", "value": True})
    candidate = tmp_path / "bad.v2.yaml"
    candidate.write_text(yaml.safe_dump(value), encoding="utf-8")
    failure = tmp_path / "bad.validation_failed.json"
    with pytest.raises(ValueError, match="exception-result"):
        validate_v2_candidate(candidate, tmp_path / "bad.validation.json",
                              failure_path=failure, tlc_jar="tlc.jar",
                              runner=successful_runner)
    assert json.loads(failure.read_text())["failed_gate"] == "tla_render"


def test_named_validation_wrapper_builds_cli_paths_and_rejects_unsafe_names(tmp_path):
    sentinel = object()
    with patch("pipeline.domain_v2_validation.validate_v2_candidate",
               return_value=sentinel) as validate:
        assert validate_domain("counter_domain", project_root=tmp_path,
                               tlc_jar="custom.jar", java="custom-java", timeout=9) is sentinel
    args, kwargs = validate.call_args
    assert args[0] == tmp_path / "domains/candidates/counter_domain.v2.yaml"
    assert args[1] == tmp_path / "domains/candidates/counter_domain.v2.validation.json"
    assert kwargs["failure_path"].name == "counter_domain.v2.validation_failed.json"
    assert kwargs["tlc_jar"] == "custom.jar" and kwargs["timeout"] == 9
    with pytest.raises(ValueError, match="safe module"):
        validate_domain("../escape", project_root=tmp_path)
