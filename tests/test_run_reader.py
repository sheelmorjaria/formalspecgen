# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Read-only operator access; fixtures are state records, not proof evidence."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import mcp_server
from pipeline import cli
from pipeline.agentic.contracts import AgentGoal, AgentRunError
from pipeline.agentic.run_reader import RunReadRequest, read_agent_run
from pipeline.agentic.state_store import AgentRunStore
from pipeline.mcp_policy import MCPPolicyViolation, authorize_mcp_invocation
from pipeline.workflow_contracts import WorkflowContext


@pytest.fixture
def store(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    root = tmp_path / "state"
    monkeypatch.setenv("FORMALSPECGEN_AGENT_STATE_ROOT", str(root))
    monkeypatch.setenv("FORMALSPECGEN_AGENT_PRINCIPAL", "operator")
    store = AgentRunStore(root)
    store.create(AgentGoal("run-001", "Inspect and verify", "a" * 40, "Probe.java", "b" * 64), "operator")
    return store


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("state", ["planned", "running", "completed", "failed", "blocked", "cancelled", "cancellation_pending"])
def test_cli_mcp_read_equivalence_and_goal_outcomes(store, state, capsys):
    store.update("run-001", "operator", lambda r: r.update(
        state=state, request_satisfied=state == "completed", claim="NO_PROOF",
        cancel_requested=state == "cancellation_pending",
        active_action={"workflow": "verify"} if state in {"running", "cancellation_pending"} else None))
    before = snapshot(store.root)
    args = cli.build_parser().parse_args(["run", "show", "run-001", "--json"])
    with patch("pipeline.agentic.supervisor.AgentSupervisor.resume", side_effect=AssertionError("no resume")), \
         patch("pipeline.agentic.action_gateway.AgentActionGateway.execute", side_effect=AssertionError("no execution")), \
         patch("subprocess.run", side_effect=AssertionError("no process")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 0
        local = json.loads(capsys.readouterr().out)
        remote = mcp_server.get_agent_run("run-001")
    assert local["operation_satisfied"] is True
    result = local["result"]
    assert result["claim"] == "NO_PROOF" and result["request_satisfied"] is True
    assert result["run_result"] == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert remote["status"] == state.upper()
    assert remote["request_satisfied"] == (state == "completed")
    assert "principal_id" not in remote["agent_run"]
    assert remote["mcp_admission"]["granted_effects"] == ["service_state_read"]
    assert result["workflow_request"] == RunReadRequest("run-001").as_dict()
    assert snapshot(store.root) == before and not list(Path.cwd().iterdir())


@pytest.mark.parametrize("run_id,code", [("missing", "RUN_NOT_FOUND"), ("../run-001", "INVALID_GOAL"),
                                         ("", "INVALID_GOAL"), ("a" * 129, "INVALID_GOAL")])
def test_lookup_failure_equivalence(store, run_id, code, capsys):
    assert cli.dispatch(cli.build_parser().parse_args(["run", "show", run_id, "--json"]),
                        cli.TerminalUI(), None, {}) == 1
    local = json.loads(capsys.readouterr().out)
    remote = mcp_server.get_agent_run(run_id)
    assert not local["operation_satisfied"] and not remote["request_satisfied"]
    assert local["result"]["code"] == remote["code"] == code


def test_ownership_and_review_integrity(store, monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_AGENT_PRINCIPAL", "other")
    assert mcp_server.get_agent_run("run-001")["code"] == "RUN_ACCESS_DENIED"
    monkeypatch.setenv("FORMALSPECGEN_AGENT_PRINCIPAL", "operator")
    receipt = store.publish_review("run-001", "operator", {"claim": "NO_PROOF"})
    store.update("run-001", "operator", lambda r: r.update(state="completed", review=receipt))
    assert mcp_server.get_agent_run("run-001")["review"] == receipt
    Path(receipt["path"]).write_text("tampered")
    assert mcp_server.get_agent_run("run-001")["code"] == "REVIEW_EVIDENCE_INVALID"


def test_corrupt_event_is_rejected(store):
    event = next(store.runs.rglob("000001.json"))
    value = json.loads(event.read_text())
    value["record"]["state"] = "completed"
    event.write_text(json.dumps(value))
    assert mcp_server.get_agent_run("run-001")["code"] == "RUN_EVIDENCE_INVALID"


@pytest.mark.parametrize("configuration", ["missing-principal", "missing-root", "relative-root", "workspace-root", "absent-store", "symlink", "writable"])
def test_operator_configuration_failures_never_create_state(store, monkeypatch, configuration):
    if configuration == "missing-principal":
        monkeypatch.delenv("FORMALSPECGEN_AGENT_PRINCIPAL")
    elif configuration == "missing-root":
        monkeypatch.delenv("FORMALSPECGEN_AGENT_STATE_ROOT")
    elif configuration == "writable":
        store.root.chmod(0o777)
    else:
        root = {"relative-root": "relative", "workspace-root": str(Path.cwd()),
                "absent-store": str(store.root.parent / "absent"), "symlink": str(store.root.parent / "link")}[configuration]
        if configuration == "symlink":
            Path(root).symlink_to(store.root)
        monkeypatch.setenv("FORMALSPECGEN_AGENT_STATE_ROOT", root)
    before = snapshot(store.root.parent)
    assert not mcp_server.get_agent_run("run-001")["request_satisfied"]
    assert snapshot(store.root.parent) == before
    assert not (store.root.parent / "absent").exists()


def test_effects_and_request_surface(store, capsys):
    with pytest.raises(MCPPolicyViolation):
        read_agent_run(RunReadRequest("run-001"), WorkflowContext.for_cli(()))
    denied = authorize_mcp_invocation("get_agent_run", mode="local", language="none",
                                      backend="builtin-supervisor", effects=("external_execution",))
    with patch("mcp_server.authorize_mcp_invocation", return_value=denied), \
         patch("pipeline.agentic.run_reader.AgentRunStore") as constructor:
        assert not mcp_server.get_agent_run("run-001")["request_satisfied"]
        constructor.assert_not_called()
    parser = cli.build_parser()
    assert "run" in cli.repl_commands(parser)
    for arguments in (["run", "resume", "run-001"], ["run", "show", "run-001", "--json", "out.json"],
                      ["run", "show", "run-001", "--principal", "other"]):
        with pytest.raises(SystemExit):
            parser.parse_args(arguments)
    capsys.readouterr()
    for value in (None, 12, "a/b", "run\x00id"):
        with pytest.raises(AgentRunError):
            RunReadRequest(value)


def test_real_run_read_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires provisioned real MCP transport")
    import anyio
    from scripts.mcp_acceptance_adapters import _run_observation
    observed = anyio.run(_run_observation)
    assert observed["state_unchanged"] and observed["workspace_unchanged"]
    assert len(observed["cli_comparisons"]) == 12
