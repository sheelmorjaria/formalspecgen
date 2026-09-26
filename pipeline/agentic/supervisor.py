# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic supervisor around admitted inspection and verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from pipeline.mcp_policy import MCPAdmission, require_mcp_effect

from .acceptance import action_succeeded, build_review
from .action_gateway import AgentActionGateway
from .contracts import AgentGoal, AgentRunError, TERMINAL_RUN_STATES
from .planner import PlannedAction, next_action
from .state_store import AgentRunStore


@dataclass
class AgentSupervisor:
    """Run a reviewed two-step goal without granting model authority.

    Planning is deterministic in this first profile.  Persisting an action
    intent before invoking it ensures a controller crash cannot silently cause
    a second verifier execution or duplicate evidence publication.
    """

    store: AgentRunStore
    gateway: AgentActionGateway
    admission: MCPAdmission

    def start(self, goal: AgentGoal, principal_id: str) -> dict[str, Any]:
        require_mcp_effect(self.admission, "service_state_read")
        require_mcp_effect(self.admission, "service_state_write")
        record, _created = self.store.create(goal, principal_id)
        if record.get("state") in TERMINAL_RUN_STATES:
            return record
        if record.get("active_action") is not None:
            return record
        return self._advance(goal, principal_id)

    def get(self, run_id: str, principal_id: str) -> dict[str, Any]:
        require_mcp_effect(self.admission, "service_state_read")
        return self.store.get(run_id, principal_id)

    def resume(self, run_id: str, principal_id: str) -> dict[str, Any]:
        """Resume only between actions; never replay an uncertain tool call."""
        require_mcp_effect(self.admission, "service_state_read")
        require_mcp_effect(self.admission, "service_state_write")
        record = self.store.get(run_id, principal_id)
        goal = self._goal(record)
        if record.get("state") in TERMINAL_RUN_STATES:
            return record
        if record.get("active_action") is not None:
            return self._block(
                goal, principal_id, "ACTION_OUTCOME_UNKNOWN",
                "an interrupted action requires operator reconciliation")
        return self._advance(goal, principal_id)

    def cancel(self, run_id: str, principal_id: str) -> dict[str, Any]:
        require_mcp_effect(self.admission, "service_state_read")
        require_mcp_effect(self.admission, "service_state_write")

        def mutate(record: dict[str, Any]) -> None:
            if record.get("state") in TERMINAL_RUN_STATES:
                return
            record["cancel_requested"] = True
            record["state"] = (
                "cancellation_pending" if record.get("active_action") else "cancelled")

        record = self.store.update(run_id, principal_id, mutate)
        if record.get("state") == "cancelled" and record.get("review") is None:
            return self._finalize(self._goal(record), principal_id, "cancelled")
        return record

    def _advance(self, goal: AgentGoal, principal_id: str) -> dict[str, Any]:
        while True:
            record = self.store.get(goal.run_id, principal_id)
            if record.get("state") in TERMINAL_RUN_STATES:
                return record
            if record.get("cancel_requested"):
                return self._finalize(goal, principal_id, "cancelled")
            try:
                action = next_action(goal, record)
            except AgentRunError as exc:
                return self._block(goal, principal_id, exc.code, str(exc))
            if action is None:
                return self._finalize(goal, principal_id, "completed")
            self._claim_action(goal, principal_id, action)
            try:
                result = self.gateway.execute(goal, action)
            except AgentRunError as exc:
                return self._record_failure(goal, principal_id, action, exc)
            record = self._record_observation(goal, principal_id, action, result)
            if record.get("cancel_requested"):
                return self._finalize(goal, principal_id, "cancelled")
            if not action_succeeded(action.workflow, result):
                return self._finalize(goal, principal_id, "failed")

    def _claim_action(
            self, goal: AgentGoal, principal_id: str,
            action: PlannedAction) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            if record.get("active_action") is not None:
                raise AgentRunError("RUN_BUSY", "another action is already active")
            if record.get("state") in TERMINAL_RUN_STATES:
                raise AgentRunError("RUN_TERMINAL", "agent run is already terminal")
            record["state"] = "running"
            record["active_action"] = action.as_dict()

        return self.store.update(goal.run_id, principal_id, mutate)

    def _record_observation(
            self, goal: AgentGoal, principal_id: str, action: PlannedAction,
            result: Mapping[str, Any]) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            active = record.get("active_action") or {}
            if active.get("sequence") != action.sequence:
                raise AgentRunError("RUN_STATE_INVALID", "active action identity changed")
            succeeded = action_succeeded(action.workflow, result)
            record.setdefault("actions", []).append({
                **action.as_dict(), "state": "completed",
                "succeeded": succeeded, "result": dict(result),
            })
            record["active_action"] = None
            if not succeeded:
                record["failure_count"] = int(record.get("failure_count", 0)) + 1
                record.setdefault("unresolved_findings", []).append({
                    "workflow": action.workflow,
                    "status": result.get("status", "UNKNOWN"),
                    "code": result.get("code"),
                    "message": result.get("message"),
                })
            record["state"] = "planned"

        return self.store.update(goal.run_id, principal_id, mutate)

    def _record_failure(
            self, goal: AgentGoal, principal_id: str, action: PlannedAction,
            error: AgentRunError) -> dict[str, Any]:
        result = error.as_dict()
        self._record_observation(goal, principal_id, action, result)
        return self._finalize(goal, principal_id, "blocked")

    def _block(
            self, goal: AgentGoal, principal_id: str,
            code: str, message: str) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            record.setdefault("unresolved_findings", []).append({
                "workflow": (record.get("active_action") or {}).get("workflow"),
                "status": "BLOCKED", "code": code, "message": message,
            })
            record["active_action"] = None

        self.store.update(goal.run_id, principal_id, mutate)
        return self._finalize(goal, principal_id, "blocked")

    def _finalize(
            self, goal: AgentGoal, principal_id: str,
            terminal_state: str) -> dict[str, Any]:
        require_mcp_effect(self.admission, "evidence_publication")
        record = self.store.get(goal.run_id, principal_id)
        if record.get("review") is not None:
            return record
        review_record = dict(record)
        review_record["state"] = terminal_state
        review = build_review(
            goal, review_record, admission=self.admission.summary())
        receipt = self.store.publish_review(goal.run_id, principal_id, review)

        def mutate(latest: dict[str, Any]) -> None:
            if latest.get("review") is not None:
                return
            latest["state"] = terminal_state
            latest["active_action"] = None
            latest["review"] = receipt
            latest["request_satisfied"] = bool(review["request_satisfied"])
            latest["claim"] = review["claim"]

        return self.store.update(goal.run_id, principal_id, mutate)

    @staticmethod
    def _goal(record: Mapping[str, Any]) -> AgentGoal:
        value = dict(record.get("goal", {}))
        value.pop("schema", None)
        for key in ("permitted_workflows", "proposed_actions", "allowed_paths",
                    "protected_paths"):
            if key in value:
                value[key] = tuple(value[key])
        return AgentGoal(**value)
