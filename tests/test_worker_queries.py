# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Synthetic stored references are proposals, not downloaded or verified bytes."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import mcp_server
from pipeline import cli
from pipeline.a2a_coordination import A2ACoordinationError, TaskStore
from pipeline.capability_registry import MCP_EFFECTS
from pipeline.mcp_policy import MCPPolicyViolation, authorize_mcp_invocation
from pipeline.worker_queries import WorkerArtifactsRequest, read_worker_artifacts
from pipeline.workflow_contracts import WorkflowContext


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def store(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema": "formalspecgen-a2a-policy-v1", "authorities": [], "workers": []}))
    policy.chmod(0o600)
    monkeypatch.setenv("FORMALSPECGEN_A2A_POLICY", str(policy))
    monkeypatch.setenv("FORMALSPECGEN_A2A_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "operator")
    store = TaskStore(tmp_path / "state")
    store.create({"work_item_id": "work-001", "principal_id": "operator", "state": "completed",
                  "request_sha256": "a" * 64, "acceptance": {"status": "pending", "claim": "NO_PROOF"},
                  "worker_result": {"patch_sha256": "b" * 64, "artifacts": [
                      {"artifact_id": "patch", "sha256": "c" * 64, "uri": "https://invalid.example/patch"}]}})
    return store


@pytest.mark.parametrize("state", ["queued", "working", "completed", "failed", "rejected", "cancelled",
                                  "dispatching", "dispatch_uncertain", "cancellation_pending", "inconsistent"])
def test_cli_mcp_reference_equivalence(store, state, capsys):
    store.update("work-001", "operator", state="completed" if state == "inconsistent" else state,
                 coordination_status="inconsistent" if state == "inconsistent" else "consistent",
                 coordination_diagnostics=[{"code": "TERMINAL_STATE_CONFLICT"}] if state == "inconsistent" else [])
    before = snapshot(store.root.parent)
    with patch("pipeline.a2a_coordination.OfficialA2AWorkerClient._run_sync", side_effect=AssertionError("no remote call")), \
         patch("subprocess.run", side_effect=AssertionError("no process")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")), \
         patch("urllib.request.urlopen", side_effect=AssertionError("no artifact retrieval")), \
         patch.object(Path, "read_bytes", side_effect=AssertionError("no artifact read")):
        assert cli.dispatch(cli.build_parser().parse_args(["worker", "artifacts", "work-001", "--json"]),
                            cli.TerminalUI(), None, {}) == 0
        local = json.loads(capsys.readouterr().out)
        remote = mcp_server.get_work_artifacts("work-001")
    result = local["result"]
    assert result["worker_result"] == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert local["operation_satisfied"] and result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert result["workflow_request"] == WorkerArtifactsRequest("work-001").as_dict()
    assert remote["status"] == ("COORDINATION_INCONSISTENT" if state == "inconsistent" else state)
    assert remote["request_satisfied"] == (state != "inconsistent")
    assert remote["acceptance"] == {"status": "pending", "claim": "NO_PROOF"}
    assert remote["artifacts"][0]["uri"] == "https://invalid.example/patch"
    assert not remote["implementation_accepted"] and not remote["artifact_bytes_validated"]
    assert not remote["artifact_retrieval_performed"]
    assert remote["mcp_admission"]["granted_effects"] == ["service_state_read"]
    assert snapshot(store.root.parent) == before and not list(Path.cwd().iterdir())


@pytest.mark.parametrize("failure,code", [("missing", "TASK_NOT_FOUND"), ("foreign", "TASK_NOT_FOUND"),
    ("tampered", "TASK_EVIDENCE_INVALID"), ("invalid", "INVALID_WORK_ITEM")])
def test_failed_queries_preserve_state(store, monkeypatch, capsys, failure, code):
    work_id = "work-001"
    if failure == "missing":
        work_id = "missing"
    elif failure == "invalid":
        work_id = "../escape"
    elif failure == "foreign":
        monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "other")
    else:
        next(store.tasks.rglob("000001.json")).write_text("{}")
    before = snapshot(store.root.parent)
    assert cli.dispatch(cli.build_parser().parse_args(["worker", "artifacts", work_id, "--json", "-"]),
                        cli.TerminalUI(), None, {}) == 1
    local = json.loads(capsys.readouterr().out)
    remote = mcp_server.get_work_artifacts(work_id)
    assert local["result"]["code"] == remote["code"] == code
    assert not local["operation_satisfied"] and not remote["request_satisfied"]
    assert snapshot(store.root.parent) == before


@pytest.mark.parametrize("kind", ["principal", "policy", "policy-writable", "state", "relative", "workspace", "symlink", "writable", "malformed-policy"])
def test_operator_configuration_denied_without_state_creation(store, monkeypatch, kind, capsys):
    if kind == "principal":
        monkeypatch.delenv("FORMALSPECGEN_A2A_PRINCIPAL")
    elif kind == "policy":
        monkeypatch.delenv("FORMALSPECGEN_A2A_POLICY")
    elif kind == "policy-writable":
        Path(os.environ["FORMALSPECGEN_A2A_POLICY"]).chmod(0o664)
    elif kind == "malformed-policy":
        Path(os.environ["FORMALSPECGEN_A2A_POLICY"]).write_text("{}")
    else:
        root = {"state": str(store.root.parent / "absent"), "relative": "relative",
                "workspace": str(Path.cwd()), "symlink": str(store.root.parent / "link"),
                "writable": str(store.root)}[kind]
        if kind == "symlink":
            Path(root).symlink_to(store.root)
        if kind == "writable":
            store.root.chmod(0o777)
        monkeypatch.setenv("FORMALSPECGEN_A2A_STATE_ROOT", root)
    before = snapshot(store.root.parent)
    assert cli.dispatch(cli.build_parser().parse_args(["worker", "artifacts", "work-001", "--json"]),
                        cli.TerminalUI(), None, {}) == 1
    local = json.loads(capsys.readouterr().out)["result"]
    remote = mcp_server.get_work_artifacts("work-001")
    assert not remote["request_satisfied"] and local["code"] == remote["code"]
    assert snapshot(store.root.parent) == before
    assert not (store.root.parent / "absent").exists()


def test_empty_references_are_not_acceptance(store):
    store.update("work-001", "operator", state="dispatch_uncertain", worker_result=None)
    result = mcp_server.get_work_artifacts("work-001")
    assert result["status"] == "dispatch_uncertain" and result["artifacts"] == []
    assert result["patch_sha256"] is None and not result["implementation_accepted"]
    assert result["acceptance"]["status"] == "pending"


def test_effects_arguments_and_unsupported_operations(store, capsys):
    request = WorkerArtifactsRequest("work-001")
    with patch("pipeline.worker_queries.configured_worker_coordinator") as configured:
        with pytest.raises(MCPPolicyViolation):
            read_worker_artifacts(request, WorkflowContext.for_cli(()))
        configured.assert_not_called()
    for effect in MCP_EFFECTS - {"service_state_read"}:
        denied = authorize_mcp_invocation("get_work_artifacts", mode="artifacts", language="none",
                                          backend="a2a-1.0", effects=(effect,))
        assert not denied.admitted
    with patch("mcp_server.authorize_mcp_invocation", return_value=denied), \
         patch("mcp_server._configured_a2a_coordinator") as configured:
        assert not mcp_server.get_work_artifacts("work-001")["request_satisfied"]
        configured.assert_not_called()
    parser = cli.build_parser()
    assert "worker" in cli.repl_commands(parser)
    for tail in (["--refresh"], ["--principal", "other"], ["--json", "out.json"]):
        with pytest.raises(SystemExit):
            parser.parse_args(["worker", "artifacts", "work-001", *tail])
    with pytest.raises(SystemExit):
        parser.parse_args(["worker", "submit", "work-001"])
    capsys.readouterr()
    for value in (None, 4, "", "a" * 129, "..", "a/b", "a\x00b"):
        with pytest.raises(A2ACoordinationError):
            WorkerArtifactsRequest(value)


def test_real_worker_artifact_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires real MCP transport")
    import anyio
    from scripts.mcp_acceptance_adapters import _worker_observation
    result = anyio.run(_worker_observation)
    assert result["state_unchanged"] and result["workspace_unchanged"]
    assert len(result["cli_comparisons"]) == 15
