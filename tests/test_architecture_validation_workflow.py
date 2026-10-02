"""Shared architecture validation tests; injected observations are not TLC evidence."""
from dataclasses import asdict, replace
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from pipeline.architecture_validation_workflow import (
    ARCHITECTURE_BUDGET, ArchitectureValidationRequest, run_architecture_validation)
from pipeline.execution import ExecutionObservation
from pipeline.lifecycle import RunLedger
from pipeline.workflow_contracts import WorkflowContext


def model():
    return {"name": "Counter", "components": [{"name": "Core", "type": "core",
        "state_variables": [{"name": "x", "type": "int", "bound": [0, 1], "initial": 0}],
        "operations": [{"name": "toggle", "contract": {"requires": "true", "ensures": "true"}}],
        "transitions": [{"operation_name": "toggle", "precondition": {"kind": "boolean", "value": True},
            "frame": ["x"], "effects": [{"target": "x", "value": {"kind": "sub",
                "left": {"kind": "integer", "value": 1}, "right": {"kind": "field", "name": "x"}}}]}]}]}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    source = tmp_path / "model.json"
    source.write_text(json.dumps(model()))
    jar = tmp_path / "tlc.jar"
    jar.write_bytes(b"fixture jar")
    monkeypatch.setattr("pipeline.isolated_tlc.config.TLC_JAR", str(jar))
    monkeypatch.setattr("pipeline.isolated_tlc.shutil.which", lambda _: "/usr/bin/java")
    monkeypatch.setattr("pipeline.isolated_tlc._java_configuration_paths", lambda _: ())
    return source


def judge(request):
    return ExecutionObservation(status="COMPLETED", exit_code=0,
        output="TLC2 Version 2.19\n" if request.tool == "tlc-provenance" else
               "Model checking completed. No error has been found.\n",
        requested_policy=asdict(request.policy), enforced_policy=asdict(request.policy), policy_compliance="ENFORCED",
        snapshot_manifest_sha256=request.snapshot.manifest_sha256, snapshot_files=request.snapshot.manifest,
        tool=request.tool, command=request.command)


def run(source, *, export="result.json", limits=None, executor=None, effects=None):
    request = ArchitectureValidationRequest(str(source), 10, export)
    context = WorkflowContext.for_cli(effects or request.required_effects(), workspace_root=source.parent,
        output_root=source.parent / "out", resource_budget=ARCHITECTURE_BUDGET | (limits or {}))
    return run_architecture_validation(request, context, executor=executor or Mock(execute=Mock(side_effect=judge)))


def test_captured_source_models_receipt_and_authoritative_paths(setup):
    original = setup.read_bytes()
    def execute(request):
        setup.write_text("changed after capture")
        return judge(request)
    result = run(setup, executor=Mock(execute=execute))
    assert result["status"] == "VERIFIED" and result["request_satisfied"]
    assert result["claim"] == "BOUNDED_ARCHITECTURE_EVIDENCE"
    assert not result["claim_limits"]["source_correspondence_proved"]
    assert result["inputs"][0]["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["model_scope"]["state_space_upper_bound"] == 2
    receipt = result["publication"]["receipt"]
    path = Path(receipt["manifest_path"])
    manifest = json.loads(path.read_text())
    assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt["manifest_sha256"]
    assert not RunLedger._validate_artifacts(path.parent, manifest["artifacts"])
    assert manifest["terminal"]["request_satisfied"]
    assert len(manifest["terminal"]["execution_stages"]) == 2
    embedded = manifest["terminal"]["semantic_bindings"]["generated_model_text"]
    for name, text in embedded.items():
        assert hashlib.sha256(text.encode()).hexdigest() == result["generated_models"][name]["sha256"]
    for identity in result["generated_models"].values():
        assert hashlib.sha256(Path(identity["path"]).read_bytes()).hexdigest() == identity["sha256"]
        assert identity["path"] in {item["path"] for item in result["publication"]["artifacts"].values()}
    exported = json.loads((setup.parent / "out/result.json").read_text())
    assert exported["generated_models"] == result["generated_models"]
    assert exported["publication"] == result["publication"]


@pytest.mark.parametrize("stage,changes", [(0, {"output": "unknown version"}),
    (0, {"policy_compliance": "NOT_ENFORCED"}), (1, {"exit_code": 12, "output": "Invariant violated"}),
    (1, {"output": ""}), (1, {"output_truncated": True}), (1, {"timed_out": True}),
    (1, {"snapshot_files": ()}), (1, {"status": "MEMORY_LIMIT_EXCEEDED"})])
def test_failed_checks_retain_observations_and_export(setup, stage, changes):
    calls = []
    def execute(request):
        index = len(calls)
        calls.append(request)
        return replace(judge(request), **changes) if index == stage else judge(request)
    result = run(setup, executor=Mock(execute=execute))
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert len(result["execution_stages"]) == stage + 1
    assert result["result_export"]["status"] == "COMMITTED"


@pytest.mark.parametrize("kind", ["missing", "symlink", "malformed", "duplicate-key", "nonfinite",
    "byte-limit", "node-limit", "depth-limit", "state-limit", "generated-limit", "duplicate-state", "domain", "symbol-collision"])
def test_rejection_before_backend_with_negative_exports(setup, kind):
    limits = {}
    if kind == "missing":
        setup.unlink()
    elif kind == "symlink":
        target = setup.with_suffix(".real")
        setup.rename(target)
        setup.symlink_to(target)
    elif kind in {"malformed", "duplicate-key", "nonfinite"}:
        setup.write_text({"malformed": "{", "duplicate-key": '{"name":"X","name":"Y"}', "nonfinite": '{"x":NaN}'}[kind])
    elif kind.endswith("limit"):
        key = {"byte-limit": "max_input_bytes", "node-limit": "max_json_nodes", "depth-limit": "max_json_depth",
               "state-limit": "max_state_space", "generated-limit": "max_generated_bytes"}[kind]
        limits[key] = 1
    else:
        value = model()
        component = value["components"][0]
        if kind == "duplicate-state":
            value["components"].append(dict(component, name="Other", transitions=[]))
        elif kind == "domain":
            value["components"].append({"name": "Other", "type": "core", "domain": "counter"})
        else:
            component["operations"][0]["name"] = "Init"
            component["transitions"][0]["operation_name"] = "Init"
        setup.write_text(json.dumps(value))
    executor = Mock(execute=Mock(side_effect=judge))
    result = run(setup, limits=limits, executor=executor)
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    executor.execute.assert_not_called()
    assert result["result_export"]["status"] == "COMMITTED"


@pytest.mark.parametrize("effect", ArchitectureValidationRequest("x").required_effects())
def test_denied_effects_stop_before_execution(setup, effect):
    request = ArchitectureValidationRequest(str(setup))
    executor = Mock(execute=Mock(side_effect=judge))
    result = run(setup, effects=tuple(item for item in request.required_effects() if item != effect), executor=executor)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()


def test_existing_export_and_publication_failures_are_no_proof(setup, monkeypatch):
    (setup.parent / "out").mkdir()
    (setup.parent / "out/result.json").write_text("preserved")
    result = run(setup)
    assert result["status"] == "RESULT_EXPORT_FAILED" and result["claim"] == "NO_PROOF"
    assert (setup.parent / "out/result.json").read_text() == "preserved"
    monkeypatch.setattr("pipeline.architecture_validation_workflow.publish_controlled_multistage_evidence",
                        Mock(side_effect=OSError("publication failed")))
    result = run(setup, export="failure.json")
    assert result["status"] == "EVIDENCE_PUBLICATION_FAILED" and result["claim"] == "NO_PROOF"
    assert result["result_export"]["status"] == "COMMITTED"


@pytest.mark.parametrize("export", ["result.json", "reports/result.json", None])
def test_cli_mcp_equivalence_and_options(setup, monkeypatch, export):
    import mcp_server
    from pipeline import cli
    monkeypatch.chdir(setup.parent)
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", str(setup.parent / "mcp-output"))
    monkeypatch.setattr("pipeline.architecture_validation_workflow.StrictSandboxExecutor", lambda: Mock(execute=judge))
    remote = mcp_server.validate_architecture(str(setup), 7, export)
    values = []
    monkeypatch.setattr(cli, "_write_json", lambda value, *_: values.append(value))
    assert cli.command_validate_architecture(SimpleNamespace(artifact=str(setup), timeout=7, json=export or "-"),
        cli.TerminalUI(Console(file=io.StringIO()), lambda _: "")) == 0
    local = values[0]
    assert local["workflow_result"]["request"] == remote["workflow_result"]["request"]
    for field in ("status", "claim", "request_satisfied", "inputs", "model_scope", "claim_limits"):
        assert local[field] == remote[field]
    assert remote["tlc"]["execution_observations"][1]["requested_policy"]["timeout_s"] <= 7


def test_real_architecture_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires provisioned TLC and delegated cgroup")
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    observation = collect_transport_observation("validate-architecture")
    assert len(observation["semantic_results"]) == 10
    assert observation["artifact_validations"]


def test_expansion_is_rejected_before_rendering(setup, monkeypatch):
    render = Mock(side_effect=AssertionError("must not render excessive output"))
    monkeypatch.setattr("pipeline.architecture_validation_workflow.render_unified_architecture", render)
    result = run(setup, limits={"max_generated_bytes": 100})
    assert not result["request_satisfied"]
    assert "rendering expansion" in result["message"]
    render.assert_not_called()


def test_late_exception_retains_provenance_observation(setup):
    def execute(request):
        if request.tool == "tlc-model-check":
            raise RuntimeError("interrupted check")
        return judge(request)
    result = run(setup, executor=Mock(execute=execute))
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert len(result["execution_stages"]) == 1
    assert result["status"] == "ARCHITECTURE_CHECK_FAILED"
    assert result["execution_stages"][0]["tool"] == "tlc-provenance"
    assert result["result_export"]["status"] == "COMMITTED"


def test_real_architecture_fail_closed_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires real MCP stdio")
    import anyio
    import tempfile
    from scripts.mcp_acceptance_adapters import _call_tool
    async def check():
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "invalid.json").write_text('{"name":"X","components":[]}')
            calls = [{"artifact_path": "missing.json", "result_export": "missing-result.json"},
                     {"artifact_path": "invalid.json", "timeout": 5, "result_export": "invalid-result.json"}]
            _, _, schema, results = await _call_tool(root, "validate_architecture", calls)
            assert {"artifact_path", "timeout", "result_export"} == set(schema["properties"])
            for result in results:
                assert result["status"] == "ARCHITECTURE_INVALID" and result["claim"] == "NO_PROOF"
                assert not result["request_satisfied"] and not result["execution_stages"]
                assert result["publication"]["status"] == "COMMITTED"
                assert result["result_export"]["status"] == "COMMITTED"
    anyio.run(check)
