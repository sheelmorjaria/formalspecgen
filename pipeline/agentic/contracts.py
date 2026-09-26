# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Typed contracts for the supervised agentic workflow."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping

from pipeline.workflow_contracts import VerificationWorkflowRequest


AGENT_GOAL_SCHEMA = "formalspecgen-agent-goal-v1"
AGENT_RUN_SCHEMA = "formalspecgen-agent-run-v1"
AGENT_REVIEW_SCHEMA = "formalspecgen-agent-review-v1"
AGENT_POLICY_VERSION = "supervised-agent-v1"
AGENT_ACTIONS = ("inspect", "verify")
TERMINAL_RUN_STATES = frozenset({"completed", "failed", "blocked", "cancelled"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AgentRunError(RuntimeError):
    """A goal or state transition failed without widening authority."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "FAIL", "claim": "NO_PROOF",
            "request_satisfied": False, "code": self.code,
            "message": str(self),
        }


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _relative_source(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise AgentRunError(
            "INVALID_SOURCE", "source must be a relative path inside the workspace")
    if any(part in {".git", ".formalspecgen"} for part in path.parts):
        raise AgentRunError("PROTECTED_SOURCE", "service and repository metadata are protected")
    return path.as_posix()


@dataclass(frozen=True)
class AgentGoal:
    """A fixed goal and authority envelope for the first supervisor profile."""

    run_id: str
    objective: str
    base_revision: str
    source: str
    source_sha256: str
    mode: str = "esc"
    backend: str = "prusti"
    permitted_workflows: tuple[str, ...] = AGENT_ACTIONS
    proposed_actions: tuple[str, ...] = AGENT_ACTIONS
    allowed_paths: tuple[str, ...] = ()
    protected_paths: tuple[str, ...] = ()
    resource_budget: Mapping[str, int] = field(default_factory=lambda: {
        "max_actions": 2,
        "max_failures": 1,
        "max_input_bytes": 1024 * 1024,
    })
    acceptance_policy: str = "verification-request-satisfied"
    task_type: str = "inspect-and-verify"
    schema: str = field(default=AGENT_GOAL_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.run_id):
            raise AgentRunError("INVALID_GOAL", "invalid run_id")
        objective = self.objective.strip()
        if not objective or len(objective) > 8192:
            raise AgentRunError("INVALID_GOAL", "objective is empty or too large")
        if not _REVISION.fullmatch(self.base_revision):
            raise AgentRunError(
                "INVALID_BASE_REVISION", "base_revision must be a full Git SHA-1")
        if not _SHA256.fullmatch(self.source_sha256):
            raise AgentRunError("INVALID_SOURCE_DIGEST", "source_sha256 is invalid")
        source = _relative_source(self.source)
        workflows = tuple(dict.fromkeys(self.permitted_workflows))
        if workflows != AGENT_ACTIONS:
            raise AgentRunError(
                "UNSUPPORTED_PLAN",
                "the supervised profile requires exactly inspect then verify")
        proposed = tuple(self.proposed_actions)
        if proposed != AGENT_ACTIONS:
            unknown = sorted(set(proposed) - set(workflows))
            raise AgentRunError(
                "UNKNOWN_ACTION" if unknown else "UNSUPPORTED_PLAN",
                ("unknown proposed actions: " + ", ".join(unknown)
                 if unknown else
                 "the proposed plan must inspect before verification"))
        allowed = tuple(dict.fromkeys(
            _relative_source(item) for item in (self.allowed_paths or (source,))))
        if source not in allowed:
            raise AgentRunError("PATH_SCOPE_DENIED", "source is outside allowed_paths")
        protected = tuple(dict.fromkeys(_relative_source(item)
                                         for item in self.protected_paths))
        budget = dict(self.resource_budget)
        supported_budget = {"max_actions", "max_failures", "max_input_bytes"}
        if set(budget) - supported_budget or any(
                not isinstance(value, int) or value < 0 for value in budget.values()):
            raise AgentRunError("INVALID_BUDGET", "agent resource budget is invalid")
        if budget.get("max_actions", 0) < len(AGENT_ACTIONS):
            raise AgentRunError(
                "INVALID_BUDGET", "inspect-and-verify requires at least two actions")
        if budget.get("max_failures", 0) < 1:
            raise AgentRunError("INVALID_BUDGET", "max_failures must be at least one")
        if budget.get("max_input_bytes", 0) < 1:
            raise AgentRunError("INVALID_BUDGET", "max_input_bytes must be positive")
        if self.acceptance_policy != "verification-request-satisfied":
            raise AgentRunError("UNSUPPORTED_ACCEPTANCE", "unsupported acceptance policy")
        if self.task_type != "inspect-and-verify":
            raise AgentRunError("UNSUPPORTED_GOAL", "unsupported agent task type")
        # This request validates mode/backend/language defaults once.  The
        # gateway constructs it again from the immutable goal before execution.
        VerificationWorkflowRequest(source, mode=self.mode, backend=self.backend)
        object.__setattr__(self, "objective", objective)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "permitted_workflows", workflows)
        object.__setattr__(self, "proposed_actions", proposed)
        object.__setattr__(self, "allowed_paths", allowed)
        object.__setattr__(self, "protected_paths", protected)
        object.__setattr__(self, "resource_budget", MappingProxyType(budget))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "objective": self.objective,
            "base_revision": self.base_revision,
            "source": self.source,
            "source_sha256": self.source_sha256,
            "mode": self.mode,
            "backend": self.backend,
            "permitted_workflows": list(self.permitted_workflows),
            "proposed_actions": list(self.proposed_actions),
            "allowed_paths": list(self.allowed_paths),
            "protected_paths": list(self.protected_paths),
            "resource_budget": dict(self.resource_budget),
            "acceptance_policy": self.acceptance_policy,
            "task_type": self.task_type,
        }

    @property
    def request_sha256(self) -> str:
        return digest(self.as_dict())

    def source_path(self, workspace_root: Path) -> Path:
        root = workspace_root.resolve()
        path = (root / self.source).resolve()
        if path != root and root not in path.parents:
            raise AgentRunError("PATH_SCOPE_DENIED", "source escapes the workspace")
        return path
