# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""A2A coordination preserves authority, identity, and acceptance boundaries."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path

import pytest

from pipeline.a2a_coordination import (
    A2ACoordinationError,
    A2ACoordinator,
    AuthorityGrant,
    CoordinationPolicy,
    RemoteTaskObservation,
    TaskStore,
    WorkItem,
    WorkerProfile,
)


REVISION = "a" * 40
DIGEST = "b" * 64


class FakeWorkerClient:
    def __init__(self, *, state="completed", changed_files=None):
        self.calls = []
        self.state = state
        self.changed_files = changed_files or ["pipeline/worker.py"]

    def _observation(self, item, state=None):
        selected = state or self.state
        result = None
        if selected == "completed":
            result = {
                "schema": "formalspecgen-worker-result-v1",
                "work_item_id": item.work_item_id,
                "base_revision": item.base_revision,
                "patch_sha256": "c" * 64,
                "changed_files": self.changed_files,
                "artifacts": [{
                    "artifact_id": "patch",
                    "sha256": "d" * 64,
                    "uri": "a2a://worker/task/patch",
                }],
            }
        return RemoteTaskObservation("remote-1", selected, result, selected)

    def submit(self, worker, item):
        self.calls.append(("submit", worker.worker_id, item.work_item_id))
        return self._observation(item)

    def get(self, worker, task_id):
        self.calls.append(("get", worker.worker_id, task_id))
        item = self.item
        return self._observation(item, "completed")

    def cancel(self, worker, task_id):
        self.calls.append(("cancel", worker.worker_id, task_id))
        return RemoteTaskObservation(task_id, "cancelled", None, "cancelled")


def _item(**changes):
    values = {
        "work_item_id": "rust-worker-001",
        "base_revision": REVISION,
        "objective": "Implement the bounded Rust verification adapter",
        "workflow": "verify",
        "variant": {"language": "rust", "backend": "prusti"},
        "allowed_paths": ("pipeline/**", "tests/**"),
        "protected_paths": ("pipeline/mcp_policy.py",),
        "acceptance_plan_ref": "verify-rust-v1",
        "authority_ref": "grant-001",
        "deliverables": ("patch", "changed-file-manifest", "test-results"),
        "requested_effects": ("workspace_read", "workspace_write_new"),
        "resource_budget": {"wall_seconds": 60},
    }
    values.update(changes)
    return WorkItem(**values)


def _coordinator(tmp_path, client=None):
    worker = WorkerProfile(
        worker_id="rust-worker", endpoint="http://127.0.0.1:9999",
        agent_card_sha256=DIGEST, workflows=("verify",),
        effects=("workspace_read", "workspace_write_new"),
        allowed_paths=("pipeline/**", "tests/**"),
        max_budget={"wall_seconds": 90})
    grant = AuthorityGrant(
        ref="grant-001", principal_id="aiderdesk", project_root=tmp_path,
        workers=(worker.worker_id,), workflows=("verify",),
        effects=("workspace_read", "workspace_write_new"),
        allowed_paths=("pipeline/**", "tests/**"),
        max_budget={"wall_seconds": 75})
    selected = client or FakeWorkerClient()
    return (
        A2ACoordinator(
            CoordinationPolicy({grant.ref: grant}, {worker.worker_id: worker}),
            TaskStore(tmp_path / "state"), selected, project_root=tmp_path),
        selected,
    )


def test_worker_completion_is_only_a_proposal(tmp_path):
    coordinator, client = _coordinator(tmp_path)
    result = coordinator.submit(_item(), "aiderdesk")

    assert result["state"] == "completed"
    assert result["worker_result"]["patch_sha256"] == "c" * 64
    assert result["acceptance"] == {"status": "pending", "claim": "NO_PROOF"}
    assert client.calls == [("submit", "rust-worker", "rust-worker-001")]


def test_duplicate_submission_is_idempotent_but_changed_request_is_rejected(tmp_path):
    coordinator, client = _coordinator(tmp_path)
    first = coordinator.submit(_item(), "aiderdesk")
    second = coordinator.submit(_item(), "aiderdesk")
    assert second == first
    assert [call[0] for call in client.calls] == ["submit"]

    with pytest.raises(A2ACoordinationError, match="different request") as conflict:
        coordinator.submit(_item(objective="Different work"), "aiderdesk")
    assert conflict.value.code == "IDEMPOTENCY_CONFLICT"


def test_authority_is_resolved_for_principal_and_cannot_be_claimed_in_payload(tmp_path):
    coordinator, client = _coordinator(tmp_path)
    with pytest.raises(A2ACoordinationError) as denied:
        coordinator.submit(_item(), "different-principal")
    assert denied.value.code == "AUTHORITY_DENIED"
    assert client.calls == []


def test_expired_authority_is_rejected_before_worker_dispatch(tmp_path):
    coordinator, client = _coordinator(tmp_path)
    grant = coordinator.policy.authorities["grant-001"]
    expired = replace(
        grant,
        expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
    coordinator.policy = CoordinationPolicy(
        {expired.ref: expired}, coordinator.policy.workers)
    with pytest.raises(A2ACoordinationError) as denied:
        coordinator.submit(_item(), "aiderdesk")
    assert denied.value.code == "AUTHORITY_EXPIRED"
    assert client.calls == []


@pytest.mark.parametrize(("change", "code"), [
    ({"requested_effects": ("workspace_read", "external_execution")},
     "AUTHORITY_DENIED"),
    ({"resource_budget": {"wall_seconds": 76}}, "BUDGET_DENIED"),
    ({"allowed_paths": ("docs/**",)}, "AUTHORITY_DENIED"),
])
def test_worker_grant_is_intersection_of_authorities(tmp_path, change, code):
    coordinator, client = _coordinator(tmp_path)
    with pytest.raises(A2ACoordinationError) as denied:
        coordinator.submit(_item(**change), "aiderdesk")
    assert denied.value.code == code
    assert client.calls == []


def test_worker_cannot_return_changes_outside_assigned_paths(tmp_path):
    client = FakeWorkerClient(changed_files=["README.md"])
    coordinator, _ = _coordinator(tmp_path, client)
    result = coordinator.submit(_item(), "aiderdesk")
    assert result["state"] == "failed"
    assert result["worker_outcome"]["code"] == "WORKER_SCOPE_VIOLATION"
    assert result["acceptance"]["status"] == "pending"


@pytest.mark.parametrize("state", ["input_required", "auth_required", "failed"])
def test_worker_lifecycle_states_do_not_become_acceptance(tmp_path, state):
    coordinator, _ = _coordinator(tmp_path, FakeWorkerClient(state=state))
    result = coordinator.submit(_item(), "aiderdesk")
    assert result["state"] == state
    assert result["acceptance"] == {"status": "pending", "claim": "NO_PROOF"}


def test_task_retrieval_is_principal_scoped(tmp_path):
    coordinator, _ = _coordinator(tmp_path)
    coordinator.submit(_item(), "aiderdesk")
    with pytest.raises(A2ACoordinationError) as hidden:
        coordinator.get("rust-worker-001", "another-principal", refresh=False)
    assert hidden.value.code == "TASK_NOT_FOUND"


def test_task_event_tampering_is_detected(tmp_path):
    coordinator, _ = _coordinator(tmp_path)
    coordinator.submit(_item(), "aiderdesk")
    event = tmp_path / "state" / "tasks" / "rust-worker-001" / "000001.json"
    value = json.loads(event.read_text(encoding="utf-8"))
    value["record"]["principal_id"] = "attacker"
    event.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(A2ACoordinationError) as invalid:
        coordinator.get("rust-worker-001", "aiderdesk", refresh=False)
    assert invalid.value.code == "TASK_EVIDENCE_INVALID"


def test_cancellation_reaches_remote_task_and_stays_non_proof(tmp_path):
    client = FakeWorkerClient(state="working")
    coordinator, _ = _coordinator(tmp_path, client)
    client.item = _item()
    submitted = coordinator.submit(client.item, "aiderdesk")
    assert submitted["state"] == "working"
    cancelled = coordinator.cancel(client.item.work_item_id, "aiderdesk")
    assert cancelled["state"] == "cancelled"
    assert cancelled["acceptance"]["claim"] == "NO_PROOF"
    assert client.calls[-1] == ("cancel", "rust-worker", "remote-1")


def test_parallel_children_share_the_authority_budget(tmp_path):
    client = FakeWorkerClient(state="working")
    coordinator, _ = _coordinator(tmp_path, client)
    first = _item(
        work_item_id="worker-one", resource_budget={"wall_seconds": 40})
    second = _item(
        work_item_id="worker-two", resource_budget={"wall_seconds": 40})
    assert coordinator.submit(first, "aiderdesk")["state"] == "working"
    with pytest.raises(A2ACoordinationError) as denied:
        coordinator.submit(second, "aiderdesk")
    assert denied.value.code == "AGGREGATE_BUDGET_DENIED"


def test_child_task_cannot_widen_parent_path_authority(tmp_path):
    coordinator, _ = _coordinator(tmp_path)
    parent = _item(
        work_item_id="parent", allowed_paths=("pipeline/workers/**",),
        resource_budget={"wall_seconds": 60})
    coordinator.submit(parent, "aiderdesk")
    child = _item(
        work_item_id="child", allowed_paths=("pipeline/**",),
        resource_budget={"wall_seconds": 20}, parent_work_item_id="parent")
    with pytest.raises(A2ACoordinationError) as denied:
        coordinator.submit(child, "aiderdesk")
    assert denied.value.code == "PARENT_AUTHORITY_DENIED"


def test_scope_rejects_repository_and_service_metadata():
    with pytest.raises(A2ACoordinationError, match="metadata is protected"):
        _item(allowed_paths=(".git/**",))
    item = _item(protected_paths=("pipeline/**",))
    with pytest.raises(A2ACoordinationError) as protected:
        A2ACoordinator._validate_result(item, {
            "schema": "formalspecgen-worker-result-v1",
            "work_item_id": item.work_item_id,
            "base_revision": item.base_revision,
            "changed_files": ["pipeline/worker.py"],
            "artifacts": [],
        })
    assert protected.value.code == "WORKER_SCOPE_VIOLATION"
