# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Internal service regressions; injected observations are not backend evidence."""
import base64
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from pipeline import domain_validation_workflow as workflow
from pipeline.domain_v2_promotion import candidate_sha256, load_candidate, load_validation_envelope
from pipeline.execution import ExecutionObservation
from pipeline.lifecycle import RunLedger
from pipeline.workflow_contracts import WorkflowContext


def candidate():
    return {"domain_name": "Toggle", "module_name": "toggle",
        "state_variables": [{"kind": "bool", "name": "bit", "initial": False}],
        "operations": [{"name": "flip", "return_type": "void", "failure_semantics": "unavailable",
            "guards": [], "frame": ["bit"], "effects": [{"id": "toggle", "target": "bit",
                "value": {"kind": "not", "expression": {"kind": "field", "name": "bit"}}}]}],
        "tlc_invariants": [{"id": "Trivial", "expression": {"kind": "boolean", "value": True}}]}


@pytest.fixture
def source(tmp_path, monkeypatch):
    source = tmp_path / "candidate.yaml"
    source.write_text(yaml.safe_dump(candidate()))
    jar = tmp_path / "fixture.jar"
    jar.write_bytes(b"fixture")
    monkeypatch.setattr("pipeline.isolated_tlc.config.TLC_JAR", str(jar))
    monkeypatch.setattr("pipeline.isolated_tlc.shutil.which", lambda _: "/usr/bin/java")
    monkeypatch.setattr("pipeline.isolated_tlc._java_configuration_paths", lambda _: ())
    return source


def observation(request):
    return ExecutionObservation(status="COMPLETED", exit_code=0,
        output="TLC2 Version 2.19\n" if request.tool == "tlc-provenance" else
            "Model checking completed. No error has been found.\n",
        requested_policy=asdict(request.policy), enforced_policy=asdict(request.policy),
        policy_compliance="ENFORCED", tool=request.tool, command=request.command,
        snapshot_manifest_sha256=request.snapshot.manifest_sha256, snapshot_files=request.snapshot.manifest)


def run(source, *, executor=None, limits=None, effects=None, export="result.json", emit=None, timeout=12):
    request = workflow.DomainValidationWorkflowRequest(source.name, timeout, emit, export)
    context = WorkflowContext.for_cli(request.required_effects() if effects is None else effects,
        workspace_root=source.parent, output_root=source.parent / "output", resource_budget=limits)
    return workflow.run_domain_validation(request, context,
        executor=executor or Mock(execute=Mock(side_effect=observation)))


def assert_receipt(result):
    receipt = result["publication"]["receipt"]
    path = Path(receipt["manifest_path"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt["manifest_sha256"]
    manifest = json.loads(path.read_text())
    assert not RunLedger._validate_artifacts(path.parent, manifest["artifacts"])
    for item in result["publication"]["artifacts"].values():
        assert hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() == item["sha256"]
    return manifest["terminal"]


def test_complete_internal_path_binds_snapshot_models_observations_and_envelope(source):
    original, digest = source.read_bytes(), candidate_sha256(load_candidate(source))
    seen = []
    def execute(request):
        source.write_text("changed: after capture")
        seen.append(request)
        return observation(request)
    result = run(source, emit="models/Toggle.tla", executor=Mock(execute=execute))
    assert result["status"] == "VALIDATED" and result["request_satisfied"]
    assert result["checks_satisfied"] and result["failed_gate"] is None
    assert result["workflow_result"]["verification"] == {
        "claim": "BOUNDED_ARCHITECTURE_EVIDENCE", "request_satisfied": True}
    assert result["candidate_sha256"] == digest
    assert result["traversal"] == {"status": "PASSED", "reachable_states": 2, "reachable_transitions": 2}
    assert not result["claim_limits"]["source_correspondence_proved"]
    assert not result["claim_limits"]["review_authenticated"]
    terminal = assert_receipt(result)
    assert terminal["semantic_bindings"]["static_findings"] == []
    assert base64.b64decode(terminal["semantic_bindings"]["captured_candidate_base64"]) == original
    assert result["inputs"][0]["sha256"] == hashlib.sha256(original).hexdigest()
    assert [item["tool"] for item in result["execution_stages"]] == ["tlc-provenance", "tlc-model-check"]
    assert all(item["policy_compliance"] == "ENFORCED" for item in result["execution_stages"])
    assert len(seen) == 2 and all(item.policy.timeout_s <= 12 for item in seen)
    envelope = load_validation_envelope(result["validation_artifact"]["path"])
    assert envelope.evidence.candidate_sha256 == digest
    assert envelope.evidence.reachable_state_count == 2
    for name, identity in result["generated_models"].items():
        model = Path(identity["path"]).read_bytes()
        assert hashlib.sha256(model).hexdigest() == identity["sha256"]
        assert model == (source.parent / "output/models" / name).read_bytes()
        assert model.decode() == terminal["semantic_bindings"]["generated_model_text"][name]
    assert all("path" not in entry for entry in result["preparation"]["generated_models"].values())
    exported = json.loads((source.parent / "output/result.json").read_text())
    assert exported["publication"] == result["publication"]
    assert exported["generated_models"] == result["generated_models"]
    assert exported["model_export"] == result["model_export"]


@pytest.mark.parametrize("kind,gate", [("malformed", "preparation"), ("invalid", "preparation"),
    ("nonutf8", "preparation"), ("static", "static_deadlock"), ("invariant", "bounded_traversal"),
    ("states", "bounded_traversal"), ("transitions", "bounded_traversal"), ("work", "bounded_traversal"),
    ("bound-report", "preparation"), ("missing", "capture"), ("bytes", "capture")])
def test_preexecution_failures_keep_negative_export_and_captured_identity(source, kind, gate):
    limits = {}
    if kind == "malformed":
        source.write_text("a: [")
    elif kind == "invalid":
        source.write_text("{}")
    elif kind == "nonutf8":
        source.write_bytes(b"\xff")
    elif kind == "missing":
        source.unlink()
    elif kind == "bytes":
        limits = {"max_input_bytes": 1}
    elif kind == "bound-report":
        limits = {"max_state_bound_bits": 1}
    elif kind in {"states", "transitions", "work"}:
        limits = {{"states": "max_states", "transitions": "max_transitions", "work": "max_work_items"}[kind]: 1}
    else:
        value = candidate()
        if kind == "invariant":
            value["tlc_invariants"][0]["expression"]["value"] = False
        else:
            value["state_variables"] = [{"kind": "int", "name": "x", "initial": 0, "bound": [0, 2]}]
            value["operations"] = [{"name": "never", "return_type": "void", "failure_semantics": "unavailable",
                "guards": [{"id": "no", "expression": {"kind": "boolean", "value": False}}],
                "effects": [], "frame": []}]
        source.write_text(yaml.safe_dump(value))
    executor = Mock(execute=Mock(side_effect=AssertionError("rejected input reached execution")))
    result = run(source, executor=executor, limits=limits)
    assert result["failed_gate"] == gate and result["claim"] == "NO_PROOF"
    assert not result["request_satisfied"] and not result["checks_satisfied"]
    assert not result["execution_stages"] and "validation_artifact" not in result
    if kind in {"states", "transitions", "work", "bound-report"}:
        assert result["code"] == "DOMAIN_CHECK_INCOMPLETE"
    assert result["result_export"]["status"] == "COMMITTED"
    terminal = assert_receipt(result)
    if kind not in {"missing", "bytes"}:
        assert base64.b64decode(terminal["semantic_bindings"]["captured_candidate_base64"]) == source.read_bytes()
        assert result["inputs"][0]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert json.loads((source.parent / "output/result.json").read_text())["claim"] == "NO_PROOF"
    executor.execute.assert_not_called()


@pytest.mark.parametrize("index,changes", [(0, {"output": "unknown"}), (0, {"policy_compliance": "NOT_ENFORCED"}),
    (1, {"exit_code": 12, "output": "counterexample"}), (1, {"output": ""}),
    (1, {"output_truncated": True}), (1, {"timed_out": True}),
    (1, {"status": "MEMORY_LIMIT_EXCEEDED"}), (1, {"snapshot_files": ()})])
def test_tlc_failure_preserves_every_observation_and_negative_export(source, index, changes):
    calls = []
    def execute(request):
        current = len(calls)
        calls.append(request)
        observed = observation(request)
        return replace(observed, **changes) if current == index else observed
    result = run(source, executor=Mock(execute=execute))
    assert result["failed_gate"] == "tlc" and result["claim"] == "NO_PROOF"
    assert not result["request_satisfied"] and len(result["execution_stages"]) == index + 1
    assert result["traversal"]["status"] == "PASSED" and result["result_export"]["status"] == "COMMITTED"
    assert assert_receipt(result)["execution_stages"] == json.loads(json.dumps(result["execution_stages"]))


def test_late_exception_cannot_erase_provenance_observation(source):
    def execute(request):
        if request.tool == "tlc-model-check":
            raise RuntimeError("interrupted check")
        return observation(request)
    result = run(source, executor=Mock(execute=execute))
    assert result["failed_gate"] == "tlc" and result["claim"] == "NO_PROOF"
    assert len(result["execution_stages"]) == 1
    assert assert_receipt(result)["execution_stages"] == json.loads(json.dumps(result["execution_stages"]))


def test_asserted_success_without_executions_is_not_accepted(source, monkeypatch):
    monkeypatch.setattr(workflow, "run_isolated_tlc", lambda *_, **__: {
        "model_check_passed": True, "execution_observations": []})
    result = run(source)
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert "validation_artifact" not in result


@pytest.mark.parametrize("denied", ["workspace_read", "external_execution", "evidence_publication", "workspace_write_new"])
def test_missing_effect_stops_before_capture_and_execution(source, monkeypatch, denied):
    monkeypatch.setattr(workflow, "capture_domain_candidate", Mock(side_effect=AssertionError("unauthorized capture")))
    effects = tuple(effect for effect in workflow.DomainValidationWorkflowRequest(source.name).required_effects() if effect != denied)
    result = run(source, effects=effects)
    assert result["claim"] == "NO_PROOF" and not result["request_satisfied"]
    assert not result["execution_stages"] and not result["inputs"]


@pytest.mark.parametrize("emit,export", [("same.tla", "same.tla"), ("same.tla", "same.cfg"),
    ("same.cfg", "result.json"), ("../candidate.yaml", "result.json"), (None, "../candidate.yaml")])
def test_output_scope_and_aliases_stop_before_dispatch(source, monkeypatch, emit, export):
    original = source.read_bytes()
    monkeypatch.setattr(workflow, "capture_domain_candidate", Mock(side_effect=AssertionError("unsafe output reached capture")))
    result = run(source, emit=emit, export=export)
    assert result["claim"] == "NO_PROOF" and not result["request_satisfied"]
    assert result["code"] == "OUTPUT_SCOPE_VIOLATION" and source.read_bytes() == original


def test_existing_model_output_is_preserved_and_failure_is_exported(source):
    out = source.parent / "output"
    out.mkdir()
    (out / "Toggle.tla").write_bytes(b"existing model")
    result = run(source, emit="Toggle.tla")
    assert result["status"] == "MODEL_EXPORT_FAILED" and not result["request_satisfied"]
    assert result["checks_satisfied"] and result["claim"] == "NO_PROOF"
    assert (out / "Toggle.tla").read_bytes() == b"existing model"
    assert not (out / "Toggle.cfg").exists()
    assert assert_receipt(result)["final_status"] == "MODEL_EXPORT_FAILED"
    assert json.loads((out / "result.json").read_text())["status"] == "MODEL_EXPORT_FAILED"


def test_existing_result_export_remains_unchanged(source):
    out = source.parent / "output"
    out.mkdir()
    (out / "result.json").write_bytes(b"existing result")
    result = run(source)
    assert result["status"] == "RESULT_EXPORT_FAILED" and result["claim"] == "NO_PROOF"
    assert not result["request_satisfied"] and result["checks_satisfied"]
    assert (out / "result.json").read_bytes() == b"existing result"
    assert result["publication"]["status"] == "COMMITTED"


def test_evidence_publication_failure_is_no_proof_with_negative_export(source, monkeypatch):
    monkeypatch.setattr(workflow, "publish_controlled_multistage_evidence", Mock(side_effect=OSError("publication failed")))
    result = run(source, emit="Toggle.tla")
    assert result["status"] == "EVIDENCE_PUBLICATION_FAILED" and result["claim"] == "NO_PROOF"
    assert not result["request_satisfied"] and result["checks_satisfied"]
    assert result["model_export"]["status"] == "COMMITTED"
    assert len(result["execution_stages"]) == 2
    assert json.loads((source.parent / "output/result.json").read_text())["status"] == "EVIDENCE_PUBLICATION_FAILED"


def test_zero_publication_budget_never_uses_default_allowance(source):
    result = run(source, limits={"max_result_bytes": 0})
    assert not result["request_satisfied"] and not result["checks_satisfied"]
    assert result["publication"]["status"] == "FAILED"
    assert not (source.parent / "output/result.json").exists()
    assert not list((source.parent / "output").rglob("*.json"))


@pytest.mark.parametrize("mode,counts", [("boolean", (4, 8)), ("async", (4, 8)), ("lock", (21, 38))])
def test_preserves_existing_actor_abstractions_and_bounds(source, mode, counts):
    value = candidate()
    value["actors"] = 2
    value["operations"][0].update(effects=[], frame=[])
    if mode == "lock":
        value["state_variables"].append({"kind": "int", "name": "mutex", "initial": 0, "bound": [0, 2]})
        value["concurrency"] = {"mode": "lock_protocol", "lock_variable": "mutex",
            "lock_states": ["FREE", "A", "B"], "unlocked_value": 0, "actor_lock_values": [1, 2],
            "linearization_points": {"flip": "effect_commit"}}
    else:
        value["operations"][0].update(return_type="boolean", failure_semantics="false_and_stutter")
        if mode == "async":
            value["execution_model"] = "async_message_passing"
    source.write_text(yaml.safe_dump(value))
    result = run(source)
    assert result["request_satisfied"], result
    assert (result["traversal"]["reachable_states"], result["traversal"]["reachable_transitions"]) == counts
    assert result["model_scope"]["actor_count"] == 2
    assert result["model_scope"]["state_bounds"]["bit"] == [False, True]
    from pipeline.domain_v2_model import state_space_upper_bound
    assert result["model_scope"]["state_space_upper_bound"] == state_space_upper_bound(load_candidate(source))
    assert result["model_export"]["status"] == "NOT_REQUESTED"


def test_missing_tlc_dependency_is_not_a_successful_check(source, monkeypatch):
    monkeypatch.setattr("pipeline.isolated_tlc.config.TLC_JAR", str(source.parent / "missing.jar"))
    result = run(source)
    assert result["failed_gate"] == "tlc" and result["claim"] == "NO_PROOF"
    assert not result["execution_stages"] and not result["request_satisfied"]
    assert result["result_export"]["status"] == "COMMITTED"


def test_outputs_cannot_alias_input_when_roots_overlap(source):
    original = source.read_bytes()
    request = workflow.DomainValidationWorkflowRequest(source.name, emit_tla=source.name, result_export="error.json")
    context = WorkflowContext.for_cli(request.required_effects(), workspace_root=source.parent, output_root=source.parent)
    result = workflow.run_domain_validation(request, context)
    assert result["code"] == "OUTPUT_SCOPE_VIOLATION" and not result["request_satisfied"]
    assert not result["execution_stages"] and source.read_bytes() == original
    assert json.loads((source.parent / "error.json").read_text())["claim"] == "NO_PROOF"


@pytest.mark.parametrize("kwargs", [{"timeout": 0}, {"timeout": True}, {"emit_tla": ""},
    {"result_export": "bad\0path"}, {"candidate_path": None}])
def test_request_rejects_invalid_fields(kwargs):
    with pytest.raises(ValueError):
        workflow.DomainValidationWorkflowRequest(**({"candidate_path": "candidate.yaml"} | kwargs))


@pytest.mark.skipif(os.environ.get("FORMALSPECGEN_REQUIRE_DOMAIN_VALIDATION_ACCEPTANCE") != "1",
                    reason="requires provisioned real TLC and strict sandbox")
def test_real_domain_validation_service(tmp_path):
    source = tmp_path / "candidate.yaml"
    source.write_text(yaml.safe_dump(candidate()))
    request = workflow.DomainValidationWorkflowRequest(source.name, emit_tla="models/Toggle.tla", result_export="result.json")
    context = WorkflowContext.for_cli(request.required_effects(), workspace_root=tmp_path, output_root=tmp_path / "output")
    result = workflow.run_domain_validation(request, context)
    assert result["status"] == "VALIDATED", result
    assert result["request_satisfied"] and len(result["execution_stages"]) == 2
    assert all(stage["policy_compliance"] == "ENFORCED" for stage in result["execution_stages"])
    assert_receipt(result)
