# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""MCP exposes only the admitted, principal-scoped A2A coordinator bridge."""

from unittest.mock import Mock, patch

import mcp_server


REVISION = "a" * 40


def _record(state="completed"):
    return {
        "work_item_id": "work-001",
        "state": state,
        "acceptance": {"status": "pending", "claim": "NO_PROOF"},
        "worker_result": {"artifacts": []},
    }


def _submit():
    return mcp_server.submit_work_item(
        "work-001", REVISION, "Implement a bounded adapter", "verify",
        {"language": "rust", "backend": "prusti"},
        ["pipeline/**"], ["pipeline/mcp_policy.py"], "verify-rust-v1",
        "grant-001", ["patch", "changed-file-manifest"],
        ["workspace_read", "workspace_write_new"], {"wall_seconds": 30},
        "rust-worker")


def test_submit_uses_server_principal_and_never_claims_acceptance(monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "aiderdesk")
    coordinator = Mock()
    coordinator.submit.return_value = _record()
    with patch("pipeline.a2a_coordination.current_git_revision", return_value=REVISION), \
            patch("mcp_server._configured_a2a_coordinator",
                  return_value=coordinator):
        result = _submit()

    assert result["status"] == "COMPLETED"
    assert result["claim"] == "NO_PROOF"
    assert result["worker_completed"] is True
    assert result["implementation_accepted"] is False
    assert result["mcp_admission"]["granted_effects"] == [
        "remote_worker_dispatch", "service_state_write", "workspace_read"]
    assert coordinator.submit.call_args.args[1:] == ("aiderdesk", "rust-worker")


def test_stale_revision_rejects_before_store_or_worker(monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "aiderdesk")
    with patch("pipeline.a2a_coordination.current_git_revision",
               return_value="b" * 40), \
            patch("mcp_server._configured_a2a_coordinator") as configured:
        result = _submit()
    configured.assert_not_called()
    assert result["status"] == "FAIL"
    assert result["claim"] == "NO_PROOF"
    assert "base_revision" in result["message"]


def test_local_read_does_not_acquire_dispatch_or_write(monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "aiderdesk")
    coordinator = Mock()
    coordinator.get.return_value = _record("working")
    with patch("mcp_server._configured_a2a_coordinator",
               return_value=coordinator) as configured:
        result = mcp_server.get_work_item("work-001", refresh=False)
    configured.assert_called_once_with(create_state=False)
    coordinator.get.assert_called_once_with(
        "work-001", "aiderdesk", refresh=False)
    assert result["mcp_admission"]["granted_effects"] == ["service_state_read"]


def test_uncertain_and_pending_states_never_satisfy_mcp_request(monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "aiderdesk")
    coordinator = Mock()
    with patch("mcp_server._configured_a2a_coordinator",
               return_value=coordinator):
        for state in ("dispatching", "dispatch_uncertain", "cancellation_pending"):
            coordinator.get.return_value = _record(state)
            result = mcp_server.get_work_item("work-001", refresh=False)
            assert result["status"] == state.upper()
            assert result["request_satisfied"] is False
            assert result["implementation_accepted"] is False


def test_conflicting_remote_outcomes_are_visible_and_unsatisfied(monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "aiderdesk")
    coordinator = Mock()
    record = _record("completed")
    record["coordination_status"] = "inconsistent"
    record["coordination_diagnostics"] = [{
        "code": "TERMINAL_STATE_CONFLICT",
        "message": "remote event cannot replace a terminal outcome",
    }]
    coordinator.get.return_value = record
    with patch("mcp_server._configured_a2a_coordinator",
               return_value=coordinator):
        result = mcp_server.get_work_item("work-001", refresh=False)

    assert result["status"] == "COORDINATION_INCONSISTENT"
    assert result["request_satisfied"] is False
    assert result["coordination_inconsistent"] is True
    assert result["worker_completed"] is True
    assert result["implementation_accepted"] is False


def test_artifact_and_cancel_routes_do_not_accept_caller_identity(monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "aiderdesk")
    coordinator = Mock()
    coordinator.artifacts.return_value = {
        "status": "completed", "work_item_id": "work-001",
        "artifacts": [{"artifact_id": "patch", "sha256": "c" * 64}],
        "patch_sha256": "d" * 64,
        "acceptance": {"status": "pending", "claim": "NO_PROOF"},
        "coordination_status": "consistent",
        "coordination_diagnostics": [],
    }
    coordinator.cancel.return_value = _record("cancelled")
    with patch("mcp_server._configured_a2a_coordinator",
               return_value=coordinator):
        artifacts = mcp_server.get_work_artifacts("work-001")
        cancelled = mcp_server.cancel_work_item("work-001")
    coordinator.artifacts.assert_called_once_with("work-001", "aiderdesk")
    coordinator.cancel.assert_called_once_with("work-001", "aiderdesk")
    assert artifacts["implementation_accepted"] is False
    assert artifacts["coordination_inconsistent"] is False
    assert cancelled["claim"] == "NO_PROOF"


def test_artifact_route_exposes_coordination_inconsistency(monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_A2A_PRINCIPAL", "aiderdesk")
    coordinator = Mock()
    coordinator.artifacts.return_value = {
        "status": "completed", "work_item_id": "work-001",
        "artifacts": [{"artifact_id": "patch", "sha256": "c" * 64}],
        "patch_sha256": "d" * 64,
        "acceptance": {"status": "pending", "claim": "NO_PROOF"},
        "coordination_status": "inconsistent",
        "coordination_diagnostics": [{
            "code": "TERMINAL_STATE_CONFLICT", "message": "conflict"}],
    }
    with patch("mcp_server._configured_a2a_coordinator",
               return_value=coordinator):
        result = mcp_server.get_work_artifacts("work-001")

    assert result["status"] == "COORDINATION_INCONSISTENT"
    assert result["request_satisfied"] is False
    assert result["coordination_inconsistent"] is True
    assert result["implementation_accepted"] is False


def test_operator_configuration_cannot_live_in_agent_workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORMALSPECGEN_A2A_POLICY", str(tmp_path / "policy.json"))
    monkeypatch.setenv("FORMALSPECGEN_A2A_STATE_ROOT", str(tmp_path / "state"))
    try:
        mcp_server._configured_a2a_coordinator(create_state=True)
    except ValueError as exc:
        assert "outside the agent workspace" in str(exc)
    else:  # pragma: no cover - the configuration must fail closed
        raise AssertionError("agent-editable A2A policy was accepted")
