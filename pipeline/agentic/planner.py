# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic action selection for the initial supervised profile."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import AgentGoal, AgentRunError


@dataclass(frozen=True)
class PlannedAction:
    sequence: int
    workflow: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence, "workflow": self.workflow,
            "reason": self.reason,
        }


def next_action(goal: AgentGoal, record: Mapping[str, Any]) -> PlannedAction | None:
    """Select only the next action from the reviewed fixed workflow set."""
    completed = tuple(
        item.get("workflow") for item in record.get("actions", ())
        if item.get("state") == "completed")
    proposed = tuple(goal.proposed_actions)
    if completed != proposed[:len(completed)]:
        raise AgentRunError("RUN_STATE_INVALID", "completed action order is invalid")
    if record.get("active_action") is not None:
        raise AgentRunError(
            "ACTION_OUTCOME_UNKNOWN",
            "an action was interrupted; automatic replay is not permitted")
    if len(completed) >= len(proposed):
        return None
    if len(record.get("actions", ())) >= goal.resource_budget["max_actions"]:
        raise AgentRunError("ACTION_BUDGET_EXHAUSTED", "agent action budget exhausted")
    workflow = proposed[len(completed)]
    return PlannedAction(
        len(completed) + 1, workflow,
        ("establish bounded structural findings" if workflow == "inspect"
         else "evaluate the approved source with the requested formal backend"),
    )
