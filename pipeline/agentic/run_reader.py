# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Read existing principal-owned runs without creating a supervisor or gateway."""
from dataclasses import dataclass
import os
import re

from pipeline.operator_configuration import operator_controlled_path
from pipeline.workflow_contracts import WorkflowContext
from .contracts import AgentRunError
from .state_store import AgentRunStore


@dataclass(frozen=True)
class RunReadRequest:
    run_id: str

    def __post_init__(self):
        if not isinstance(self.run_id, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.run_id):
            raise AgentRunError("INVALID_GOAL", "invalid run_id")

    def required_effects(self) -> tuple[str, ...]:
        return ("service_state_read",)

    def as_dict(self) -> dict:
        return {"schema": "formalspecgen-run-read-request-v1", "run_id": self.run_id}


def run_response(record: dict) -> dict:
    """Preserve the run's outcome; reading it is not new verification evidence."""
    return {
        "status": str(record.get("state", "unknown")).upper(),
        "claim": record.get("claim", "NO_PROOF"),
        "request_satisfied": bool(record.get("request_satisfied", False)),
        "run_id": record.get("run_id"),
        "agent_run": {key: value for key, value in record.items() if key != "principal_id"},
        "review": record.get("review"),
        "source_changes_applied": False,
        "human_approval_granted": False,
    }


def read_agent_run(request: RunReadRequest, context: WorkflowContext) -> dict:
    context.require("service_state_read")
    principal = os.environ.get("FORMALSPECGEN_AGENT_PRINCIPAL", "").strip()
    if not principal:
        raise ValueError("FORMALSPECGEN_AGENT_PRINCIPAL is not configured")
    root = operator_controlled_path("FORMALSPECGEN_AGENT_STATE_ROOT")
    record = AgentRunStore(root, create=False).get(request.run_id, principal)
    return run_response(record)
