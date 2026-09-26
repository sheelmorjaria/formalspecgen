# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""MCP admission and typed responses for the supervised agent profile."""

from __future__ import annotations

from pathlib import Path
import hashlib
from unittest.mock import patch

import mcp_server


REVISION = "a" * 40


def _environment(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    state = tmp_path / "agent-state"
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("FORMALSPECGEN_AGENT_STATE_ROOT", str(state))
    monkeypatch.setenv("FORMALSPECGEN_AGENT_PRINCIPAL", "aiderdesk")
    return source


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inspect(_source):
    return {"status": "INSPECTED", "claim": "NO_PROOF",
            "request_satisfied": False, "findings": []}


def _verify(*_args):
    return {
        "status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
        "request_satisfied": True,
        "evidence": {
            "publication_status": "COMMITTED", "run_id": "proof-001",
            "manifest_path": "/evidence/manifest.json",
            "manifest_sha256": "b" * 64,
        },
    }


def test_mcp_starts_reads_and_returns_evidence_backed_review(tmp_path, monkeypatch):
    _environment(tmp_path, monkeypatch)
    with patch("pipeline.a2a_coordination.current_git_revision", return_value=REVISION), \
            patch("mcp_server.inspect_code", side_effect=_inspect), \
            patch("mcp_server.verify_code", side_effect=_verify):
        result = mcp_server.start_agent_run(
            "agent-001", "Inspect and verify", REVISION, "Probe.java", _digest(Path("Probe.java")),
            proposed_actions=["inspect", "verify"],
            protected_paths=["contracts/Reviewed.jml"])

    assert result["status"] == "COMPLETED"
    assert result["request_satisfied"] is True
    assert result["claim"] == "DEDUCTIVE_PROOF"
    assert result["source_changes_applied"] is False
    assert result["human_approval_granted"] is False
    assert result["mcp_admission"]["profile"] == "supervised-java-inspect-verify"
    assert result["agent_run"]["goal"]["protected_paths"] == ["contracts/Reviewed.jml"]
    assert Path(result["review"]["path"]).is_file()

    read = mcp_server.get_agent_run("agent-001")
    assert read["status"] == "COMPLETED"
    assert read["mcp_admission"]["granted_effects"] == ["service_state_read"]


def test_mcp_rejects_unknown_actions_before_state_or_workflows(tmp_path, monkeypatch):
    _environment(tmp_path, monkeypatch)
    with patch("pipeline.a2a_coordination.current_git_revision", return_value=REVISION), \
            patch("mcp_server.inspect_code") as inspect, \
            patch("mcp_server.verify_code") as verify:
        result = mcp_server.start_agent_run(
            "agent-002", "Try an invented action", REVISION, "Probe.java", _digest(Path("Probe.java")),
            proposed_actions=["inspect", "shell", "verify"])
    assert result["status"] == "FAIL"
    assert result["code"] == "UNKNOWN_ACTION"
    assert result["request_satisfied"] is False
    inspect.assert_not_called()
    verify.assert_not_called()


def test_mcp_caller_cannot_widen_path_or_resource_ceiling(tmp_path, monkeypatch):
    _environment(tmp_path, monkeypatch)
    with patch("pipeline.a2a_coordination.current_git_revision", return_value=REVISION), \
            patch("mcp_server.inspect_code") as inspect, \
            patch("mcp_server.verify_code") as verify:
        path = mcp_server.start_agent_run(
            "agent-path", "Request extra read scope", REVISION, "Probe.java", _digest(Path("Probe.java")),
            allowed_paths=["Probe.java", "secrets/**"])
        budget = mcp_server.start_agent_run(
            "agent-budget", "Request extra attempts", REVISION, "Probe.java", _digest(Path("Probe.java")),
            resource_budget={"max_actions": 3})
    assert path["status"] == "FAIL"
    assert "approved source path" in path["message"]
    assert budget["status"] == "FAIL"
    assert "server ceiling" in budget["message"]
    inspect.assert_not_called()
    verify.assert_not_called()


def test_mcp_rejects_stale_revision_and_non_java_profile(tmp_path, monkeypatch):
    source = _environment(tmp_path, monkeypatch)
    with patch("pipeline.a2a_coordination.current_git_revision", return_value="b" * 40):
        stale = mcp_server.start_agent_run(
            "agent-003", "Inspect stale source", REVISION, source.name, _digest(source))
    assert stale["status"] == "FAIL"
    assert "base_revision" in stale["message"]

    Path("probe.rs").write_text("fn main() {}\n", encoding="utf-8")
    native = mcp_server.start_agent_run(
        "agent-004", "Unsupported initial profile", REVISION, "probe.rs", _digest(Path("probe.rs")))
    assert native["status"] == "ISOLATION_UNSUPPORTED"
    assert native["request_satisfied"] is False


def test_mcp_rejects_source_bytes_outside_approved_snapshot(tmp_path, monkeypatch):
    _environment(tmp_path, monkeypatch)
    with patch("pipeline.a2a_coordination.current_git_revision", return_value=REVISION), \
            patch("mcp_server.inspect_code") as inspect:
        result = mcp_server.start_agent_run(
            "agent-drift", "Reject source drift", REVISION, "Probe.java", "0" * 64)
    assert result["status"] == "FAIL"
    assert "approved source bytes" in result["message"]
    inspect.assert_not_called()


def test_agent_service_configuration_and_principal_are_operator_controlled(
        tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("FORMALSPECGEN_AGENT_STATE_ROOT", str(workspace / "state"))
    monkeypatch.setenv("FORMALSPECGEN_AGENT_PRINCIPAL", "aiderdesk")
    result = mcp_server.get_agent_run("agent-001")
    assert result["status"] == "FAIL"
    assert "outside the agent workspace" in result["message"]

    monkeypatch.setenv("FORMALSPECGEN_AGENT_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.delenv("FORMALSPECGEN_AGENT_PRINCIPAL")
    result = mcp_server.get_agent_run("agent-001")
    assert result["status"] == "FAIL"
    assert "PRINCIPAL" in result["message"].upper() or "principal" in result["message"]
