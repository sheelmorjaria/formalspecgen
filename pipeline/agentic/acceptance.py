# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic goal-level acceptance and review rendering."""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import AGENT_POLICY_VERSION, AGENT_REVIEW_SCHEMA, AgentGoal


def action_succeeded(workflow: str, result: Mapping[str, Any]) -> bool:
    if workflow == "inspect":
        return result.get("status") == "INSPECTED"
    if workflow == "verify":
        evidence = result.get("evidence")
        return bool(
            result.get("request_satisfied") is True
            and isinstance(evidence, Mapping)
            and evidence.get("publication_status") == "COMMITTED")
    return False


def build_review(
        goal: AgentGoal, record: Mapping[str, Any], *,
        admission: Mapping[str, Any]) -> dict[str, Any]:
    actions = list(record.get("actions", ()))
    verification = next(
        (item.get("result", {}) for item in actions
         if item.get("workflow") == "verify"), {})
    inspection = next(
        (item.get("result", {}) for item in actions
         if item.get("workflow") == "inspect"), {})
    satisfied = (
        len(actions) == 2
        and all(item.get("state") == "completed" for item in actions)
        and action_succeeded("inspect", inspection)
        and action_succeeded("verify", verification))
    return {
        "schema": AGENT_REVIEW_SCHEMA,
        "run_id": goal.run_id,
        "goal_sha256": goal.request_sha256,
        "objective": goal.objective,
        "task_type": goal.task_type,
        "base_revision": goal.base_revision,
        "source": goal.source,
        "source_sha256": goal.source_sha256,
        "status": "COMPLETED" if satisfied else str(record.get("state", "FAILED")).upper(),
        "claim": verification.get("claim", "NO_PROOF"),
        "request_satisfied": satisfied,
        "inspection": inspection,
        "verification": verification,
        "unresolved_findings": list(record.get("unresolved_findings", ())),
        "actions": [
            {key: value for key, value in item.items() if key != "result"}
            for item in actions
        ],
        "authority": dict(admission),
        "agent_policy_version": AGENT_POLICY_VERSION,
        "human_approval": {
            "required_for": [
                "contract changes", "source application", "promotion",
                "signing", "trust policy changes", "merge",
            ],
            "granted": False,
        },
    }
