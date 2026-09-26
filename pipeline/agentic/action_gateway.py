# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Trusted gateway from a supervised plan to admitted application workflows."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from pipeline.mcp_policy import (
    MCPAdmission,
    MCPPolicyViolation,
    require_mcp_effect,
)

from .contracts import AgentGoal, AgentRunError
from .planner import PlannedAction


class AgentActionGateway:
    """Execute only named, pre-authorized actions against one source snapshot."""

    def __init__(
            self, *, workspace_root: Path, admission: MCPAdmission,
            inspect: Callable[..., dict[str, Any]],
            verify: Callable[..., dict[str, Any]]):
        self.workspace_root = workspace_root.resolve()
        self.admission = admission
        self._inspect = inspect
        self._verify = verify

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def execute(self, goal: AgentGoal, action: PlannedAction) -> dict[str, Any]:
        if action.workflow not in goal.permitted_workflows:
            raise AgentRunError("ACTION_NOT_AUTHORIZED", "planned workflow is not permitted")
        path = goal.source_path(self.workspace_root)
        if not path.is_file():
            raise AgentRunError("SOURCE_UNAVAILABLE", "approved source is unavailable")
        self._require("workspace_read")
        if self._sha256(path) != goal.source_sha256:
            raise AgentRunError(
                "SOURCE_SNAPSHOT_MISMATCH",
                "source bytes changed after the goal was approved")
        if action.workflow == "inspect":
            result = self._inspect(goal.source)
        elif action.workflow == "verify":
            self._require("external_execution")
            self._require("evidence_publication")
            result = self._verify(goal.source, goal.mode, goal.backend)
        else:  # defensive even though the planner is closed over AGENT_ACTIONS
            raise AgentRunError("UNKNOWN_ACTION", "the plan requested an unknown action")
        if not isinstance(result, dict):
            raise AgentRunError("ACTION_RESULT_INVALID", "workflow result is not structured")
        if self._sha256(path) != goal.source_sha256:
            raise AgentRunError(
                "SOURCE_SNAPSHOT_MISMATCH", "source changed while the action was running")
        return self._bounded_result(result)

    def _require(self, effect: str) -> None:
        try:
            require_mcp_effect(self.admission, effect)
        except MCPPolicyViolation as exc:
            raise AgentRunError("EFFECT_NOT_AUTHORIZED", str(exc)) from exc

    @staticmethod
    def _bounded_result(result: Mapping[str, Any]) -> dict[str, Any]:
        """Retain authoritative fields while leaving raw logs in child evidence."""
        retained = {
            key: value for key, value in result.items()
            if key not in {"output", "execution_stages"}
        }
        encoded = json.dumps(retained, default=str).encode("utf-8")
        if len(encoded) > 2 * 1024 * 1024:
            raise AgentRunError(
                "ACTION_RESULT_LIMIT_EXCEEDED", "workflow result exceeds the run limit")
        return retained
