# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""CLI/MCP domain contracts; injected observations are not TLC acceptance."""
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from rich.console import Console

import mcp_server
from pipeline import cli, domain_validation_workflow as workflow
from pipeline.execution import ExecutionObservation
from pipeline.lifecycle import RunLedger
from pipeline.mcp_policy import authorize_mcp_invocation
from pipeline.workflow_contracts import WorkflowContext


def candidate():
    return {"domain_name": "Toggle", "module_name": "toggle",
        "state_variables": [{"kind": "bool", "name": "bit", "initial": False}],
        "operations": [{"name": "flip", "return_type": "void", "failure_semantics": "unavailable",
            "guards": [], "frame": ["bit"], "effects": [{"id": "toggle", "target": "bit",
                "value": {"kind": "not", "expression": {"kind": "field", "name": "bit"}}}]}],
        "tlc_invariants": [{"id": "Trivial", "expression": {"kind": "boolean", "value": True}}]}


def observation(request):
    return ExecutionObservation(status="COMPLETED", exit_code=0,
        output="TLC2 Version 2.19\n" if request.tool == "tlc-provenance" else
            "Model checking completed. No error has been found.\n",
        requested_policy=asdict(request.policy), enforced_policy=asdict(request.policy),
        policy_compliance="ENFORCED", tool=request.tool, command=request.command,
        snapshot_manifest_sha256=request.snapshot.manifest_sha256, snapshot_files=request.snapshot.manifest)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "domains/candidates/toggle.v2.yaml"
    source.parent.mkdir(parents=True)
    source.write_text(yaml.safe_dump(candidate()))
    jar = tmp_path / "tlc.jar"; jar.write_bytes(b"fixture")
    monkeypatch.setattr("pipeline.isolated_tlc.config.TLC_JAR", str(jar))
    monkeypatch.setattr("pipeline.isolated_tlc.shutil.which", lambda _: "/usr/bin/java")
    monkeypatch.setattr("pipeline.isolated_tlc._java_configuration_paths", lambda _: ())
    executor = Mock(execute=Mock(side_effect=observation))
    monkeypatch.setattr(workflow, "StrictSandboxExecutor", lambda: executor)
    return source, executor


def semantic(result):
    return {key: result.get(key) for key in ("status", "claim", "request_satisfied", "checks_satisfied",
        "failed_gate", "inputs", "candidate_sha256", "model_scope", "traversal", "claim_limits")}


def assert_receipt(result):
    receipt = result["publication"]["receipt"]
    path = Path(receipt["manifest_path"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt["manifest_sha256"]
    manifest = json.loads(path.read_text())
    assert not RunLedger._validate_artifacts(path.parent, manifest["artifacts"])
    assert manifest["terminal"]["execution_stages"] == json.loads(json.dumps(result["execution_stages"]))
    return manifest["terminal"]


@pytest.mark.parametrize("exports", [False, True])
def test_cli_mcp_equivalence_and_options(setup, monkeypatch, capsys, exports):
    source, executor = setup
    options = {"timeout": 30, "max_states": 7, "max_transitions": 9, "max_work_items": 11}
    if exports: options.update(emit_tla="models/Toggle.tla", result_export="result.json")
    remote = mcp_server.validate_domain("toggle.v2.yaml", **options)
    assert remote["status"] == "VALIDATED" and remote["request_satisfied"]
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", "unused")
    args = cli.build_parser().parse_args(["validate-domain", "toggle.v2.yaml", "--timeout", "30",
        "--max-states", "7", "--max-transitions", "9", "--max-work-items", "11",
        "--json", "result.json" if exports else "-", *(["--emit-tla", "models/Toggle.tla"] if exports else [])])
    ui = cli.TerminalUI(Console(file=io.StringIO()))
    assert cli.command_validate_domain(args, ui) == 0
    local = json.loads(Path("result.json").read_text()) if exports else json.loads(capsys.readouterr().out)
    assert semantic(local) == semantic(remote)
    assert local["workflow_result"]["request"] == remote["workflow_result"]["request"]
    assert remote["workflow_result"]["admission"]["profile"] == "bounded-domain-validation"
    assert len(executor.execute.call_args_list) == 4
    assert all(call.args[0].policy.timeout_s <= 30 for call in executor.execute.call_args_list)
    assert_receipt(remote); assert_receipt(local)
    if exports:
        assert (source.parents[2] / "models/Toggle.tla").is_file()
        assert (source.parents[2] / "models/Toggle.cfg").is_file()
        assert remote["model_export"]["status"] == "COMMITTED"
    # Validation does not mutate or authenticate legacy review sidecars.
    assert not source.with_suffix(".validation.json").exists()


@pytest.mark.parametrize("kind,gate", [("malformed", "preparation"), ("invariant", "bounded_traversal"),
    ("deadlock", "static_deadlock"), ("max_states", "bounded_traversal"),
    ("max_transitions", "bounded_traversal"), ("max_work_items", "bounded_traversal"),
    ("unsafe", "capture"), ("symlink", "capture")])
def test_adapter_negative_results_retain_evidence_and_never_execute(setup, kind, gate):
    source, executor = setup
    options = {}
    if kind == "malformed": source.write_text("a: [")
    elif kind in {"invariant", "deadlock"}:
        value = candidate()
        if kind == "invariant": value["tlc_invariants"][0]["expression"]["value"] = False
        else:
            value["state_variables"] = [{"kind": "int", "name": "x", "initial": 0, "bound": [0, 2]}]
            value["operations"] = [{"name": "never", "return_type": "void", "failure_semantics": "unavailable",
                "guards": [{"id": "no", "expression": {"kind": "boolean", "value": False}}],
                "effects": [], "frame": []}]
        source.write_text(yaml.safe_dump(value))
    elif kind.startswith("max_"): options[kind] = 1
    elif kind == "unsafe": options["project_root"] = "../outside"
    else:
        target = source.with_suffix(".real"); source.rename(target); source.symlink_to(target)
    result = mcp_server.validate_domain("toggle", result_export="negative.json", **options)
    assert result["failed_gate"] == gate and result["claim"] == "NO_PROOF"
    assert not result["request_satisfied"] and not result["checks_satisfied"]
    executor.execute.assert_not_called()
    assert_receipt(result)
    assert result["result_export"]["status"] == "COMMITTED"


def test_unavailable_tlc_and_publication_failures_are_not_proof(setup, monkeypatch):
    source, executor = setup
    monkeypatch.setattr("pipeline.isolated_tlc.config.TLC_JAR", "/absent/tlc.jar")
    missing = mcp_server.validate_domain("toggle")
    assert missing["failed_gate"] == "tlc" and missing["claim"] == "NO_PROOF"
    executor.execute.assert_not_called()
    assert_receipt(missing)
    monkeypatch.setattr("pipeline.isolated_tlc.config.TLC_JAR", str(source.parents[2] / "tlc.jar"))
    output = source.parents[2] / ".formalspecgen/mcp-output"
    (output / "collision.json").write_text("preserved")
    failed = mcp_server.validate_domain("toggle", result_export="collision.json")
    assert failed["checks_satisfied"] and failed["status"] == "RESULT_EXPORT_FAILED"
    assert not failed["request_satisfied"] and failed["claim"] == "NO_PROOF"
    assert (output / "collision.json").read_text() == "preserved"
    monkeypatch.setattr(workflow, "publish_controlled_multistage_evidence", Mock(side_effect=OSError("publication denied")))
    failed = mcp_server.validate_domain("toggle")
    assert failed["checks_satisfied"] and len(failed["execution_stages"]) == 2
    assert failed["status"] == "EVIDENCE_PUBLICATION_FAILED" and failed["claim"] == "NO_PROOF"


@pytest.mark.parametrize("field,value", [("name", "../escape"), ("name", "bad.json"), ("name", None),
    ("project_root", ""), ("timeout", 0), ("max_states", True), ("max_states", 100_001),
    ("max_transitions", -1), ("max_work_items", 0), ("emit_tla", ""), ("result_export", "bad\0name")])
def test_invalid_public_options_reject_before_capture(setup, field, value):
    _, executor = setup
    result = mcp_server.validate_domain(**({"name": "toggle"} | {field: value}))
    assert result["code"] == "INVALID_REQUEST" and result["claim"] == "NO_PROOF"
    executor.execute.assert_not_called()


@pytest.mark.parametrize("effect", workflow.DomainValidationWorkflowRequest("candidate").required_effects())
def test_admission_requires_every_effect_and_cannot_gain_other_authority(effect):
    effects = workflow.DomainValidationWorkflowRequest("candidate").required_effects()
    args = {"mode": "validate", "language": "model", "backend": "tlc"}
    assert not authorize_mcp_invocation("validate_domain", **args, effects=tuple(x for x in effects if x != effect)).admitted
    assert not authorize_mcp_invocation("validate_domain", **args, effects=effects + ("protected_signing",)).admitted
    assert not authorize_mcp_invocation("validate_domain", **args, effects=effects, provider="openai").admitted


def test_request_and_parent_limits_only_tighten_traversal(setup):
    source, executor = setup
    request = workflow.DomainValidationWorkflowRequest(str(source), max_states=8)
    context = WorkflowContext.for_cli(request.required_effects(), workspace_root=source.parents[2],
        output_root=source.parents[2] / "output", resource_budget={"max_states": 1})
    result = workflow.run_domain_validation(request, context)
    assert result["failed_gate"] == "bounded_traversal" and result["claim"] == "NO_PROOF"
    assert assert_receipt(result)["semantic_bindings"]["resource_limits"]["max_states"] == 1
    executor.execute.assert_not_called()


@pytest.mark.parametrize("mutation", [None, "different-candidate", "stale", "tampered"])
def test_human_promotion_selects_published_validation_artifact(setup, mutation):
    from pipeline.domain_v2_promotion import candidate_sha256, load_candidate
    source, _ = setup
    result = mcp_server.validate_domain("toggle")
    artifact = Path(result["validation_artifact"]["path"])
    if mutation in {"different-candidate", "stale"}:
        value = yaml.safe_load(source.read_text())
        value["state_variables"][0]["initial"] = True
        source.write_text(yaml.safe_dump(value))
    elif mutation == "tampered":
        envelope = json.loads(artifact.read_text())
        envelope["evidence"]["reachable_state_count"] += 1
        artifact.write_text(json.dumps(envelope))
    accepted = (candidate_sha256(load_candidate(source)) if mutation == "different-candidate"
                else result["candidate_sha256"])
    args = cli.build_parser().parse_args(["promote-domain", "toggle", "--validation-evidence", str(artifact),
                                         "--accept-candidate-sha256", accepted])
    code = cli.command_promote_domain(args, cli.TerminalUI(Console(file=io.StringIO())))
    destination = source.parents[2] / "domains/v2/toggle.json"
    if mutation:
        assert code == 2 and not destination.exists()
    else:
        assert code == 0
        reviewed = json.loads(destination.read_text())
        assert reviewed["accepted_candidate_sha256"] == result["candidate_sha256"]
        assert reviewed["accepted_evidence_sha256"] == result["validation_evidence"]["evidence_sha256"]
    # No corresponding agent approval/promotion route was introduced.
    assert not authorize_mcp_invocation("promote_domain", mode="promote", language="model", backend="builtin", effects=()).admitted


def test_cli_output_escape_and_mcp_admission_denial_stop_before_service(setup, monkeypatch):
    source, executor = setup
    args = cli.build_parser().parse_args(["validate-domain", "toggle", "--emit-tla", str(source.parents[3] / "outside.tla")])
    assert cli.command_validate_domain(args, cli.TerminalUI(Console(file=io.StringIO()))) == 1
    denied = authorize_mcp_invocation("validate_domain", mode="unapproved", language="model", backend="tlc", effects=())
    monkeypatch.setattr(mcp_server, "authorize_mcp_invocation", lambda *_args, **_kwargs: denied)
    service = Mock(); monkeypatch.setattr(workflow, "run_domain_validation", service)
    assert mcp_server.validate_domain("toggle")["status"] == "ISOLATION_UNSUPPORTED"
    service.assert_not_called(); executor.execute.assert_not_called()


@pytest.mark.skipif(os.environ.get("FORMALSPECGEN_REQUIRE_DOMAIN_VALIDATION_ACCEPTANCE") != "1",
                    reason="requires real MCP transport, TLC and delegated strict sandbox")
def test_real_domain_transport():
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    result = collect_transport_observation("validate-domain")
    assert result["server"] and "validate_domain" in result["discovered_tools"]
    assert {"valid", "invariant", "deadlock", "state-limit", "transition-limit", "work-item-limit",
            "malformed", "unsafe", "tlc-unavailable", "result-export-failure", "evidence-publication-failure"}.issubset(result["variants"])
    assert result["cli_comparisons"] and result["artifact_validations"]
