# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Local worker artifact-reference queries; never retrieval or acceptance."""
from dataclasses import dataclass
import os
from pathlib import Path
import re

from .a2a_coordination import (
    A2ACoordinationError, A2ACoordinator, CoordinationPolicy,
    OfficialA2AWorkerClient, TaskStore,
)
from .operator_configuration import operator_controlled_path
from .workflow_contracts import WorkflowContext


@dataclass(frozen=True)
class WorkerArtifactsRequest:
    work_item_id: str

    def __post_init__(self):
        if not isinstance(self.work_item_id, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.work_item_id):
            raise A2ACoordinationError("INVALID_WORK_ITEM", "invalid work_item_id")

    def required_effects(self) -> tuple[str, ...]:
        return ("service_state_read",)

    def as_dict(self) -> dict:
        return {"schema": "formalspecgen-worker-artifacts-request-v1",
                "work_item_id": self.work_item_id}


def configured_worker_coordinator(*, create_state: bool) -> A2ACoordinator:
    """The existing coordinator, configured only by the deployment operator."""
    policy = operator_controlled_path("FORMALSPECGEN_A2A_POLICY", require_file=True)
    root = operator_controlled_path("FORMALSPECGEN_A2A_STATE_ROOT")
    return A2ACoordinator(CoordinationPolicy.load(policy),
        TaskStore(root, create=create_state), OfficialA2AWorkerClient(), project_root=Path.cwd())


def read_worker_artifacts(request: WorkerArtifactsRequest, context: WorkflowContext,
                          *, coordinator: A2ACoordinator | None = None,
                          principal: str | None = None) -> dict:
    """Dependencies are supplied by trusted adapters, never by request fields."""
    context.require("service_state_read")
    if principal is None:
        principal = os.environ.get("FORMALSPECGEN_A2A_PRINCIPAL", "").strip()
    if not principal:
        raise ValueError("FORMALSPECGEN_A2A_PRINCIPAL is not configured")
    if coordinator is None:
        coordinator = configured_worker_coordinator(create_state=False)
    result = coordinator.artifacts(request.work_item_id, principal)
    inconsistent = result.get("coordination_status") == "inconsistent"
    return {
        **result,
        "status": "COORDINATION_INCONSISTENT" if inconsistent else result["status"],
        "claim": "NO_PROOF", "request_satisfied": not inconsistent,
        "coordination_inconsistent": inconsistent,
        "implementation_accepted": False,
        "artifact_retrieval_performed": False,
        "artifact_bytes_validated": False,
    }
