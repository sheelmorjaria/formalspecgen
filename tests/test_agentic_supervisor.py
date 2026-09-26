# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""The supervised agent remains inside existing permission/evidence boundaries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pipeline.agentic.action_gateway import AgentActionGateway
from pipeline.agentic.contracts import AgentGoal, AgentRunError
from pipeline.agentic.state_store import AgentRunStore
from pipeline.agentic.supervisor import AgentSupervisor
from pipeline.mcp_policy import authorize_mcp_invocation


REVISION = "a" * 40


def _admission(*, full=True):
    effects = (
        "workspace_read", "external_execution", "evidence_publication",
        "service_state_read", "service_state_write") if full else (
        "workspace_read", "service_state_read", "service_state_write")
    return authorize_mcp_invocation(
        "start_agent_run", mode="supervise", language="java",
        backend="openjml", effects=effects)


def _goal(source: Path, **changes):
    values = {
        "run_id": "agent-001",
        "objective": "Inspect and verify the approved component",
        "base_revision": REVISION,
        "source": source.name,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    values.update(changes)
    return AgentGoal(**values)


def _result(status="VERIFIED", *, satisfied=True):
    return {
        "status": status,
        "claim": "DEDUCTIVE_PROOF" if satisfied else "NO_PROOF",
        "request_satisfied": satisfied,
        "evidence": {
            "publication_status": "COMMITTED",
            "run_id": "proof-001",
            "manifest_path": "/evidence/manifest.json",
            "manifest_sha256": "b" * 64,
        },
        "execution": {"policy_compliance": "ENFORCED"},
        "output": "raw output remains in child evidence",
        "execution_stages": [{"output": "not duplicated"}],
    }


def _supervisor(tmp_path, source, *, inspect=None, verify=None, admission=None):
    authority = admission or _admission()
    gateway = AgentActionGateway(
        workspace_root=tmp_path, admission=authority,
        inspect=inspect or (lambda _source: {
            "status": "INSPECTED", "claim": "NO_PROOF",
            "request_satisfied": False, "findings": []}),
        verify=verify or (lambda *_args: _result()),
    )
    return AgentSupervisor(AgentRunStore(tmp_path / "state"), gateway, authority)


def test_successful_goal_publishes_review_bound_to_child_evidence(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    supervisor = _supervisor(tmp_path, source)

    record = supervisor.start(_goal(source), "aiderdesk")

    assert record["state"] == "completed"
    assert record["request_satisfied"] is True
    assert record["claim"] == "DEDUCTIVE_PROOF"
    assert [item["workflow"] for item in record["actions"]] == ["inspect", "verify"]
    assert "output" not in record["actions"][1]["result"]
    receipt = record["review"]
    assert receipt["status"] == "COMMITTED"
    review = json.loads(Path(receipt["path"]).read_text(encoding="utf-8"))
    assert review["verification"]["evidence"]["run_id"] == "proof-001"
    assert review["source_sha256"] == _goal(source).source_sha256
    assert review["human_approval"]["granted"] is False

    # An identical start is idempotent and does not call the workflows again.
    assert supervisor.start(_goal(source), "aiderdesk")["review"] == receipt


@pytest.mark.parametrize(("actions", "code"), [
    (("verify",), "UNSUPPORTED_PLAN"),
    (("inspect", "shell", "verify"), "UNKNOWN_ACTION"),
    (("verify", "inspect"), "UNSUPPORTED_PLAN"),
])
def test_model_action_proposals_cannot_change_the_reviewed_plan(
        tmp_path, actions, code):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    with pytest.raises(AgentRunError) as error:
        _goal(source, proposed_actions=actions)
    assert error.value.code == code


def test_source_change_after_goal_binding_blocks_before_any_action(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    goal = _goal(source)
    calls = []
    source.write_text("public class Probe { int changed; }\n", encoding="utf-8")
    supervisor = _supervisor(
        tmp_path, source,
        inspect=lambda *_args: calls.append("inspect"),
        verify=lambda *_args: calls.append("verify"))

    record = supervisor.start(goal, "aiderdesk")

    assert record["state"] == "blocked"
    assert record["request_satisfied"] is False
    assert record["unresolved_findings"][0]["code"] == "SOURCE_SNAPSHOT_MISMATCH"
    assert calls == []


def test_negative_verification_is_reported_without_agent_override(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    supervisor = _supervisor(
        tmp_path, source,
        verify=lambda *_args: _result("VERIFY_FAILED", satisfied=False))

    record = supervisor.start(_goal(source), "aiderdesk")

    assert record["state"] == "failed"
    assert record["request_satisfied"] is False
    assert record["claim"] == "NO_PROOF"
    assert record["failure_count"] == 1
    assert record["unresolved_findings"][0]["status"] == "VERIFY_FAILED"


def test_interrupted_action_is_blocked_instead_of_replayed(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    supervisor = _supervisor(tmp_path, source)
    goal = _goal(source)
    supervisor.store.create(goal, "aiderdesk")
    supervisor.store.update("agent-001", "aiderdesk", lambda record: record.update({
        "state": "running",
        "active_action": {"sequence": 1, "workflow": "inspect", "reason": "test"},
    }))

    record = supervisor.resume("agent-001", "aiderdesk")

    assert record["state"] == "blocked"
    assert record["unresolved_findings"][0]["code"] == "ACTION_OUTCOME_UNKNOWN"
    assert record["actions"] == []


def test_restart_between_actions_resumes_without_repeating_inspection(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    calls = []
    supervisor = _supervisor(
        tmp_path, source,
        inspect=lambda *_args: calls.append("inspect"),
        verify=lambda *_args: (calls.append("verify") or _result()))
    goal = _goal(source)
    supervisor.store.create(goal, "aiderdesk")
    supervisor.store.update("agent-001", "aiderdesk", lambda record: record.update({
        "state": "planned",
        "actions": [{
            "sequence": 1, "workflow": "inspect", "reason": "recorded",
            "state": "completed", "succeeded": True,
            "result": {"status": "INSPECTED", "findings": []},
        }],
    }))

    record = supervisor.resume("agent-001", "aiderdesk")

    assert record["state"] == "completed"
    assert calls == ["verify"]


def test_cancelled_goal_is_terminal_but_never_accepted(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    supervisor = _supervisor(tmp_path, source)
    supervisor.store.create(_goal(source), "aiderdesk")

    record = supervisor.cancel("agent-001", "aiderdesk")

    assert record["state"] == "cancelled"
    assert record["request_satisfied"] is False
    assert record["claim"] == "NO_PROOF"
    assert Path(record["review"]["path"]).is_file()


def test_principal_scope_and_event_integrity_are_enforced(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    store = AgentRunStore(tmp_path / "state")
    store.create(_goal(source), "owner")
    with pytest.raises(AgentRunError, match="another principal"):
        store.get("agent-001", "intruder")

    event = tmp_path / "state" / "runs" / "agent-001" / "000001.json"
    value = json.loads(event.read_text(encoding="utf-8"))
    value["record"]["state"] = "completed"
    event.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(AgentRunError) as error:
        store.get("agent-001", "owner")
    assert error.value.code == "RUN_EVIDENCE_INVALID"


def test_terminal_review_tampering_is_detected_on_retrieval(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    supervisor = _supervisor(tmp_path, source)
    record = supervisor.start(_goal(source), "owner")
    review = Path(record["review"]["path"])
    review.write_text(review.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(AgentRunError) as error:
        supervisor.get("agent-001", "owner")
    assert error.value.code == "REVIEW_EVIDENCE_INVALID"


def test_missing_execution_authority_blocks_at_gateway(tmp_path):
    source = tmp_path / "Probe.java"
    source.write_text("public class Probe {}\n", encoding="utf-8")
    # A fabricated attenuated admission cannot match the executing profile.
    authority = _admission(full=False)
    assert authority.admitted is False
    supervisor = _supervisor(tmp_path, source, admission=authority)
    with pytest.raises(Exception):
        supervisor.start(_goal(source), "aiderdesk")
