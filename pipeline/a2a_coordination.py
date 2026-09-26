# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Permission-scoped A2A work coordination.

Workers produce candidate patches and artifact references. A completed A2A
task is deliberately not an accepted implementation, a proof, or permission
to merge. Acceptance remains a separate, revision-bound trusted workflow.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import math
import os
import re
import tempfile
import threading
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

from .capability_registry import MCP_EFFECTS


WORK_ITEM_SCHEMA = "formalspecgen-work-item-v1"
WORKER_RESULT_SCHEMA = "formalspecgen-worker-result-v1"
COORDINATION_RECORD_SCHEMA = "formalspecgen-a2a-task-record-v1"
COORDINATION_POLICY_SCHEMA = "formalspecgen-a2a-policy-v1"
COORDINATION_AUDIT_SCHEMA = "formalspecgen-a2a-task-event-v1"
TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "rejected"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DELIVERABLES = frozenset({
    "patch", "changed-file-manifest", "test-results", "evidence-references",
})


class A2ACoordinationError(RuntimeError):
    """A coordination request failed before it could widen authority."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "FAIL", "claim": "NO_PROOF", "request_satisfied": False,
            "code": self.code, "message": str(self),
        }


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lease_deadline(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _scope(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise A2ACoordinationError("INVALID_PATH_SCOPE", f"unsafe path scope: {value}")
    if any(part in {".git", ".formalspecgen"} for part in path.parts):
        raise A2ACoordinationError(
            "PROTECTED_PATH_SCOPE", f"service or repository metadata is protected: {value}")
    wildcard_parts = [part for part in path.parts if any(mark in part for mark in "*?[")]
    if wildcard_parts and not (len(wildcard_parts) == 1 and path.parts[-1] == "**"):
        raise A2ACoordinationError(
            "INVALID_PATH_SCOPE", "only a trailing '/**' wildcard is supported")
    return path.as_posix()


def _scope_prefix(value: str) -> tuple[str, bool]:
    return (value[:-3].rstrip("/"), True) if value.endswith("/**") else (value, False)


def _scope_contains(container: str, candidate: str) -> bool:
    container_value, container_tree = _scope_prefix(container)
    candidate_value, candidate_tree = _scope_prefix(candidate)
    if not container_tree:
        return not candidate_tree and container_value == candidate_value
    return (candidate_value == container_value
            or candidate_value.startswith(container_value + "/"))


def _path_allowed(path: str, scopes: tuple[str, ...]) -> bool:
    return any(fnmatchcase(path, item) if item.endswith("/**")
               else path == item for item in scopes)


@dataclass(frozen=True)
class WorkItem:
    work_item_id: str
    base_revision: str
    objective: str
    workflow: str
    variant: Mapping[str, str]
    allowed_paths: tuple[str, ...]
    protected_paths: tuple[str, ...]
    acceptance_plan_ref: str
    authority_ref: str
    deliverables: tuple[str, ...]
    requested_effects: tuple[str, ...]
    resource_budget: Mapping[str, int] = field(default_factory=dict)
    parent_work_item_id: str | None = None
    schema: str = field(default=WORK_ITEM_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.work_item_id):
            raise A2ACoordinationError("INVALID_WORK_ITEM", "invalid work_item_id")
        if not _GIT_REVISION.fullmatch(self.base_revision):
            raise A2ACoordinationError(
                "INVALID_BASE_REVISION", "base_revision must be a full Git SHA-1")
        if not self.objective.strip() or len(self.objective) > 8192:
            raise A2ACoordinationError("INVALID_WORK_ITEM", "objective is empty or too large")
        for value, name in ((self.workflow, "workflow"),
                            (self.acceptance_plan_ref, "acceptance_plan_ref"),
                            (self.authority_ref, "authority_ref")):
            if not _IDENTIFIER.fullmatch(value):
                raise A2ACoordinationError("INVALID_WORK_ITEM", f"invalid {name}")
        allowed = tuple(sorted(set(_scope(item) for item in self.allowed_paths)))
        protected = tuple(sorted(set(_scope(item) for item in self.protected_paths)))
        if not allowed:
            raise A2ACoordinationError("INVALID_WORK_ITEM", "allowed_paths cannot be empty")
        effects = tuple(sorted(set(self.requested_effects)))
        unknown = sorted(set(effects) - MCP_EFFECTS)
        if unknown:
            raise A2ACoordinationError(
                "UNKNOWN_EFFECT", "unknown requested effects: " + ", ".join(unknown))
        deliverables = tuple(sorted(set(self.deliverables)))
        if not deliverables or not set(deliverables).issubset(_DELIVERABLES):
            raise A2ACoordinationError("INVALID_WORK_ITEM", "unsupported deliverable set")
        variant = {str(key): str(value) for key, value in self.variant.items()}
        budget = dict(self.resource_budget)
        if any(not _IDENTIFIER.fullmatch(str(key)) or not isinstance(value, int)
               or value < 0 for key, value in budget.items()):
            raise A2ACoordinationError("INVALID_BUDGET", "invalid resource budget")
        if self.parent_work_item_id is not None:
            if (not _IDENTIFIER.fullmatch(self.parent_work_item_id)
                    or self.parent_work_item_id == self.work_item_id):
                raise A2ACoordinationError(
                    "INVALID_WORK_ITEM", "invalid parent_work_item_id")
        object.__setattr__(self, "objective", self.objective.strip())
        object.__setattr__(self, "variant", variant)
        object.__setattr__(self, "allowed_paths", allowed)
        object.__setattr__(self, "protected_paths", protected)
        object.__setattr__(self, "deliverables", deliverables)
        object.__setattr__(self, "requested_effects", effects)
        object.__setattr__(self, "resource_budget", budget)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["variant"] = dict(self.variant)
        value["resource_budget"] = dict(self.resource_budget)
        return value

    @property
    def request_sha256(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class AuthorityGrant:
    ref: str
    principal_id: str
    project_root: Path
    workers: tuple[str, ...]
    workflows: tuple[str, ...]
    effects: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    max_budget: Mapping[str, int]
    expires_at: str | None = None

    def __post_init__(self) -> None:
        unknown = sorted(set(self.effects) - MCP_EFFECTS)
        if unknown:
            raise A2ACoordinationError("POLICY_INVALID", "authority has unknown effects")
        object.__setattr__(self, "project_root", self.project_root.resolve())
        object.__setattr__(self, "allowed_paths", tuple(_scope(x) for x in self.allowed_paths))
        object.__setattr__(self, "max_budget", dict(self.max_budget))
        if self.expires_at is not None:
            try:
                expires = datetime.fromisoformat(self.expires_at)
            except ValueError as exc:
                raise A2ACoordinationError(
                    "POLICY_INVALID", "invalid authority expiry") from exc
            if expires.tzinfo is None:
                raise A2ACoordinationError(
                    "POLICY_INVALID", "authority expiry must include a timezone")

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self), "project_root": str(self.project_root),
            "max_budget": dict(self.max_budget),
        }


@dataclass(frozen=True)
class WorkerProfile:
    worker_id: str
    endpoint: str
    agent_card_sha256: str
    workflows: tuple[str, ...]
    effects: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    max_budget: Mapping[str, int]
    auth_token_env: str | None = None

    def __post_init__(self) -> None:
        parsed = urlparse(self.endpoint)
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise A2ACoordinationError(
                "POLICY_INVALID", "worker endpoint must use HTTPS (HTTP is loopback-only)")
        if not _SHA256.fullmatch(self.agent_card_sha256):
            raise A2ACoordinationError("POLICY_INVALID", "worker Agent Card digest is required")
        unknown = sorted(set(self.effects) - MCP_EFFECTS)
        if unknown:
            raise A2ACoordinationError("POLICY_INVALID", "worker has unknown effects")
        object.__setattr__(self, "allowed_paths", tuple(_scope(x) for x in self.allowed_paths))
        object.__setattr__(self, "max_budget", dict(self.max_budget))

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["max_budget"] = dict(self.max_budget)
        return value


@dataclass(frozen=True)
class CoordinationPolicy:
    authorities: Mapping[str, AuthorityGrant]
    workers: Mapping[str, WorkerProfile]

    @classmethod
    def load(cls, path: Path) -> "CoordinationPolicy":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise A2ACoordinationError("POLICY_UNAVAILABLE", str(exc)) from exc
        if value.get("schema") != COORDINATION_POLICY_SCHEMA:
            raise A2ACoordinationError("POLICY_INVALID", "unsupported coordination policy")
        authorities = {}
        for item in value.get("authorities", []):
            grant = AuthorityGrant(
                ref=item["ref"], principal_id=item["principal_id"],
                project_root=Path(item["project_root"]), workers=tuple(item["workers"]),
                workflows=tuple(item["workflows"]), effects=tuple(item["effects"]),
                allowed_paths=tuple(item["allowed_paths"]),
                max_budget=item.get("max_budget", {}),
                expires_at=item.get("expires_at"),
            )
            if grant.ref in authorities:
                raise A2ACoordinationError("POLICY_INVALID", "duplicate authority ref")
            authorities[grant.ref] = grant
        workers = {}
        for item in value.get("workers", []):
            worker = WorkerProfile(
                worker_id=item["worker_id"], endpoint=item["endpoint"],
                agent_card_sha256=item["agent_card_sha256"],
                workflows=tuple(item["workflows"]), effects=tuple(item["effects"]),
                allowed_paths=tuple(item["allowed_paths"]),
                max_budget=item.get("max_budget", {}),
                auth_token_env=item.get("auth_token_env"),
            )
            if worker.worker_id in workers:
                raise A2ACoordinationError("POLICY_INVALID", "duplicate worker id")
            workers[worker.worker_id] = worker
        return cls(authorities, workers)


@dataclass(frozen=True)
class RemoteTaskObservation:
    remote_task_id: str
    state: str
    result: Mapping[str, Any] | None = None
    message: str = ""


class WorkerClient(Protocol):
    def submit(self, worker: WorkerProfile, work_item: WorkItem) -> RemoteTaskObservation: ...
    def get(self, worker: WorkerProfile, task_id: str) -> RemoteTaskObservation: ...
    def cancel(self, worker: WorkerProfile, task_id: str) -> RemoteTaskObservation: ...
    def reconcile(
            self, worker: WorkerProfile,
            work_item: WorkItem) -> RemoteTaskObservation | None: ...


class TaskStore:
    """Append-only authoritative task events with principal-scoped reads."""

    def __init__(self, root: Path, *, create: bool = True):
        self.root = root.resolve()
        self.tasks = self.root / "tasks"
        if create:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.tasks.mkdir(exist_ok=True, mode=0o700)
        elif not self.tasks.is_dir():
            raise A2ACoordinationError(
                "TASK_STORE_UNAVAILABLE", "coordination task store is unavailable")
        self.lock_path = self.root / ".lock"

    def _directory(self, work_item_id: str) -> Path:
        if not _IDENTIFIER.fullmatch(work_item_id):
            raise A2ACoordinationError("INVALID_WORK_ITEM", "invalid work_item_id")
        return self.tasks / work_item_id

    def _locked(self, *, write: bool = True):
        if write:
            handle = self.lock_path.open("a+b")
            operation = fcntl.LOCK_EX
        else:
            try:
                handle = self.lock_path.open("rb")
            except FileNotFoundError as exc:
                raise A2ACoordinationError(
                    "TASK_STORE_UNAVAILABLE",
                    "coordination task store is unavailable") from exc
            operation = fcntl.LOCK_SH
        fcntl.flock(handle.fileno(), operation)
        return handle

    @staticmethod
    def _events(directory: Path) -> list[Path]:
        return sorted(directory.glob("[0-9][0-9][0-9][0-9][0-9][0-9].json"))

    def _load_unlocked(self, work_item_id: str) -> dict[str, Any]:
        directory = self._directory(work_item_id)
        events = self._events(directory)
        if not events:
            raise A2ACoordinationError("TASK_NOT_FOUND", "work item does not exist")
        previous = None
        record = None
        for index, path in enumerate(events, start=1):
            value = json.loads(path.read_text(encoding="utf-8"))
            valid_header = (
                value.get("schema") == COORDINATION_AUDIT_SCHEMA
                and value.get("sequence") == index
                and value.get("previous_sha256") == previous
            )
            if not valid_header:
                raise A2ACoordinationError(
                    "TASK_EVIDENCE_INVALID", "task event chain is invalid")
            event_without_digest = dict(value)
            observed = event_without_digest.pop("sha256", None)
            actual = _digest(event_without_digest)
            if observed != actual:
                raise A2ACoordinationError(
                    "TASK_EVIDENCE_INVALID", "task event was altered")
            previous = observed
            record = value.get("record")
        if not isinstance(record, dict):
            raise A2ACoordinationError(
                "TASK_EVIDENCE_INVALID", "task record is missing")
        return record

    def _append_unlocked(self, record: Mapping[str, Any]) -> dict[str, Any]:
        directory = self._directory(str(record["work_item_id"]))
        directory.mkdir(mode=0o700, exist_ok=True)
        events = self._events(directory)
        previous = None
        if events:
            previous = json.loads(
                events[-1].read_text(encoding="utf-8"))["sha256"]
        event = {
            "schema": COORDINATION_AUDIT_SCHEMA,
            "sequence": len(events) + 1,
            "previous_sha256": previous,
            "record": dict(record),
            "recorded_at": _now(),
        }
        event["sha256"] = _digest(event)
        destination = directory / f"{len(events) + 1:06d}.json"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".event-", dir=directory)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(_canonical_bytes(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, destination)
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return dict(record)

    def _all_latest_unlocked(self) -> list[dict[str, Any]]:
        records = []
        for directory in sorted(self.tasks.iterdir()):
            if directory.is_dir() and _IDENTIFIER.fullmatch(directory.name):
                records.append(self._load_unlocked(directory.name))
        return records

    @staticmethod
    def _budget(record: Mapping[str, Any]) -> Mapping[str, int]:
        work_item = record.get("work_item")
        return (work_item.get("resource_budget", {})
                if isinstance(work_item, Mapping) else {})

    def _check_aggregate_budget_unlocked(
            self, record: Mapping[str, Any],
            aggregate_ceiling: Mapping[str, int]) -> None:
        current = self._all_latest_unlocked()
        active = [
            item for item in current
            if item.get("state") not in TERMINAL_STATES
            and item.get("authority_sha256") == record.get("authority_sha256")
            and item.get("principal_id") == record.get("principal_id")
        ]
        requested = self._budget(record)
        for key, ceiling in aggregate_ceiling.items():
            total = int(requested.get(key, 0)) + sum(
                int(self._budget(item).get(key, 0)) for item in active)
            if total > ceiling:
                raise A2ACoordinationError(
                    "AGGREGATE_BUDGET_DENIED",
                    f"active worker tasks exceed aggregate budget: {key}")

        work_item = record.get("work_item", {})
        parent_id = work_item.get("parent_work_item_id")
        if parent_id is None:
            return
        parent = self._load_unlocked(str(parent_id))
        self._authorize(parent, str(record.get("principal_id")))
        parent_item = parent.get("work_item", {})
        if not set(work_item.get("requested_effects", ())).issubset(
                parent_item.get("requested_effects", ())):
            raise A2ACoordinationError(
                "PARENT_AUTHORITY_DENIED", "child task widens parent effects")
        for scope in work_item.get("allowed_paths", ()):
            if not any(_scope_contains(parent_scope, scope)
                       for parent_scope in parent_item.get("allowed_paths", ())):
                raise A2ACoordinationError(
                    "PARENT_AUTHORITY_DENIED", "child task widens parent path scope")
        child_protected = tuple(work_item.get("protected_paths", ()))
        for parent_scope in parent_item.get("protected_paths", ()):
            if not any(_scope_contains(scope, parent_scope)
                       for scope in child_protected):
                raise A2ACoordinationError(
                    "PARENT_AUTHORITY_DENIED",
                    "child task drops a parent protected path scope")
        siblings = [
            item for item in current
            if item.get("state") not in TERMINAL_STATES
            and item.get("work_item", {}).get("parent_work_item_id") == parent_id
        ]
        for key, ceiling in self._budget(parent).items():
            total = int(requested.get(key, 0)) + sum(
                int(self._budget(item).get(key, 0)) for item in siblings)
            if total > ceiling:
                raise A2ACoordinationError(
                    "PARENT_BUDGET_DENIED",
                    f"child tasks exceed parent budget: {key}")

    def create(
            self, record: Mapping[str, Any], *,
            aggregate_ceiling: Mapping[str, int] | None = None,
            ) -> tuple[dict[str, Any], bool]:
        with self._locked() as lock:
            try:
                existing = self._load_unlocked(str(record["work_item_id"]))
            except A2ACoordinationError as exc:
                if exc.code != "TASK_NOT_FOUND":
                    raise
            else:
                if existing.get("request_sha256") != record.get("request_sha256"):
                    raise A2ACoordinationError(
                        "IDEMPOTENCY_CONFLICT",
                        "work_item_id is already bound to a different request")
                return existing, False
            self._check_aggregate_budget_unlocked(
                record, aggregate_ceiling or {})
            created = self._append_unlocked(record)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return created, True

    def begin_dispatch(
            self, work_item_id: str,
            principal_id: str, *, owner_id: str,
            lease_seconds: float) -> tuple[dict[str, Any], bool]:
        """Atomically claim the pre-dispatch task before any network call."""
        with self._locked() as lock:
            record = self._load_unlocked(work_item_id)
            self._authorize(record, principal_id)
            if (record.get("state") in TERMINAL_STATES
                    or record.get("dispatch_state", "not_started") != "not_started"):
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return record, False
            attempt_id = str(uuid.uuid4())
            record.update({
                "state": "dispatching",
                "dispatch_state": "in_flight",
                "dispatch_attempt_id": attempt_id,
                "dispatch_owner_id": owner_id,
                "dispatch_lease_expires_at": _lease_deadline(lease_seconds),
                "worker_outcome": {
                    "status": "dispatching",
                    "message": "worker submission is in flight",
                },
                "updated_at": _now(),
            })
            updated = self._append_unlocked(record)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return updated, True

    def renew_dispatch_lease(
            self, work_item_id: str, principal_id: str, *,
            attempt_id: str, owner_id: str,
            lease_seconds: float) -> bool:
        """Renew only the live dispatch attempt owned by this coordinator."""
        with self._locked() as lock:
            record = self._load_unlocked(work_item_id)
            self._authorize(record, principal_id)
            owned = (
                record.get("state") not in TERMINAL_STATES
                and record.get("dispatch_state") == "in_flight"
                and record.get("dispatch_attempt_id") == attempt_id
                and record.get("dispatch_owner_id") == owner_id
            )
            if owned:
                record.update({
                    "dispatch_lease_expires_at": _lease_deadline(lease_seconds),
                    "updated_at": _now(),
                })
                self._append_unlocked(record)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return owned

    @staticmethod
    def _lease_expired(value: Any, now: datetime) -> bool:
        try:
            deadline = datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise A2ACoordinationError(
                "TASK_EVIDENCE_INVALID", "dispatch lease is invalid") from exc
        if deadline.tzinfo is None:
            raise A2ACoordinationError(
                "TASK_EVIDENCE_INVALID", "dispatch lease has no timezone")
        return deadline <= now

    def claim_reconciliation(
            self, work_item_id: str, principal_id: str, *,
            owner_id: str, lease_seconds: float,
            now: datetime | None = None) -> tuple[dict[str, Any], bool]:
        """Claim recovery only after dispatch ownership is absent or expired."""
        observed_at = now or datetime.now(timezone.utc)
        with self._locked() as lock:
            record = self._load_unlocked(work_item_id)
            self._authorize(record, principal_id)
            if (record.get("state") in TERMINAL_STATES
                    or record.get("remote_task_id")):
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return record, False
            dispatch_state = record.get("dispatch_state")
            if dispatch_state == "in_flight":
                if not self._lease_expired(
                        record.get("dispatch_lease_expires_at"), observed_at):
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                    return record, False
            elif dispatch_state == "recovering":
                if not self._lease_expired(
                        record.get("recovery_lease_expires_at"), observed_at):
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                    return record, False
            elif dispatch_state != "uncertain":
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return record, False
            if not record.get("dispatch_attempt_id"):
                record["dispatch_attempt_id"] = str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    "formalspecgen-dispatch:" + str(record["request_sha256"])))
            record.update({
                "state": ("cancellation_pending"
                          if record.get("cancellation_requested")
                          else "dispatch_uncertain"),
                "dispatch_state": "recovering",
                "recovery_owner_id": owner_id,
                "recovery_lease_expires_at": (
                    observed_at + timedelta(seconds=lease_seconds)).isoformat(),
                "worker_outcome": {
                    "status": "reconciling",
                    "message": "reconciling an unresolved dispatch attempt",
                },
                "updated_at": observed_at.isoformat(),
            })
            updated = self._append_unlocked(record)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return updated, True

    @staticmethod
    def _add_diagnostic(
            record: dict[str, Any], code: str, message: str,
            **details: Any) -> None:
        diagnostic = {
            "code": code, "message": message, "observed_at": _now(),
            **details,
        }
        diagnostics = list(record.get("coordination_diagnostics", ()))
        diagnostics.append(diagnostic)
        record["coordination_diagnostics"] = diagnostics[-64:]
        record["coordination_diagnostic_count"] = int(
            record.get("coordination_diagnostic_count", 0)) + 1

    def transition_remote_event(
            self, work_item_id: str, principal_id: str, *,
            attempt_id: str, event_kind: str,
            remote_task_id: str | None = None,
            remote_state: str | None = None,
            worker_result: Mapping[str, Any] | None = None,
            operation: str | None = None,
            code: str | None = None,
            message: str = "") -> dict[str, Any]:
        """Apply an attempt-bound observation or RPC failure atomically."""
        with self._locked() as lock:
            record = self._load_unlocked(work_item_id)
            self._authorize(record, principal_id)
            if record.get("dispatch_attempt_id") != attempt_id:
                self._add_diagnostic(
                    record, "STALE_DISPATCH_ATTEMPT",
                    "event belongs to another dispatch attempt",
                    event_kind=event_kind, attempt_id=attempt_id)
                record["updated_at"] = _now()
                updated = self._append_unlocked(record)
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return updated
            bound_remote_id = record.get("remote_task_id")
            if (remote_task_id and bound_remote_id
                    and remote_task_id != bound_remote_id):
                self._add_diagnostic(
                    record, "REMOTE_TASK_ID_CONFLICT",
                    "event identifies another remote task",
                    event_kind=event_kind, remote_task_id=remote_task_id)
                record.update({
                    "coordination_status": "inconsistent",
                    "updated_at": _now(),
                })
                updated = self._append_unlocked(record)
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return updated

            current_terminal = record.get("state") in TERMINAL_STATES
            if current_terminal:
                if event_kind == "observation":
                    same = (
                        remote_state == record.get("remote_state")
                        and (dict(worker_result)
                             if worker_result is not None else None)
                        == record.get("worker_result")
                    )
                    if same:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                        return record
                    incoming_terminal = remote_state in TERMINAL_STATES
                    diagnostic_code = (
                        "TERMINAL_STATE_CONFLICT" if incoming_terminal
                        else "STALE_REMOTE_OBSERVATION")
                    self._add_diagnostic(
                        record, diagnostic_code,
                        "remote event cannot replace a terminal outcome",
                        remote_state=remote_state,
                        remote_task_id=remote_task_id)
                    if incoming_terminal:
                        record["coordination_status"] = "inconsistent"
                else:
                    self._add_diagnostic(
                        record, ("LATE_PROTOCOL_ERROR"
                                 if event_kind == "protocol_error"
                                 else "LATE_TRANSPORT_ERROR"),
                        "remote error arrived after a terminal outcome",
                        operation=operation, error_code=code)
                record["updated_at"] = _now()
                updated = self._append_unlocked(record)
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return updated

            if event_kind == "protocol_error":
                remote_terminal = remote_state in TERMINAL_STATES
                record.update({
                    "state": "failed" if remote_terminal else "dispatch_uncertain",
                    "dispatch_state": "confirmed",
                    "remote_state": remote_state,
                    "remote_task_id": remote_task_id,
                    "worker_outcome": {
                        "status": "failed" if remote_terminal
                        else "remote_observation_invalid",
                        "code": code, "message": message,
                    },
                    "acceptance": {"status": "pending", "claim": "NO_PROOF"},
                })
                self._add_diagnostic(
                    record, code or "WORKER_RESULT_INVALID", message,
                    operation="observation", remote_state=remote_state)
            elif event_kind == "transport_error":
                cancellation_requested = bool(
                    record.get("cancellation_requested", False))
                if operation == "cancel":
                    record.update({
                        "state": "cancellation_pending",
                        "cancellation_status": "uncertain",
                        "worker_outcome": {
                            "status": "cancellation_uncertain",
                            "code": code, "message": message,
                        },
                    })
                else:
                    record.update({
                        "state": ("cancellation_pending"
                                  if cancellation_requested
                                  else "dispatch_uncertain"),
                        "dispatch_state": "uncertain",
                        "worker_outcome": {
                            "status": ("reconciliation_failed"
                                       if operation == "reconcile"
                                       else "dispatch_uncertain"),
                            "code": code, "message": message,
                        },
                    })
                self._add_diagnostic(
                    record, code or "REMOTE_TRANSPORT_ERROR", message,
                    operation=operation)
            elif event_kind == "observation" and remote_state is not None:
                cancellation_requested = bool(
                    record.get("cancellation_requested", False))
                terminal = remote_state in TERMINAL_STATES
                state = (
                    "cancellation_pending"
                    if cancellation_requested and not terminal
                    else remote_state)
                record.update({
                    "state": state,
                    "dispatch_state": "confirmed",
                    "remote_state": remote_state,
                    "remote_task_id": remote_task_id,
                    "worker_result": (dict(worker_result)
                                      if worker_result is not None else None),
                    "worker_outcome": {
                        "status": remote_state, "message": message},
                    "acceptance": {"status": "pending", "claim": "NO_PROOF"},
                })
                if cancellation_requested:
                    record["cancellation_status"] = (
                        "remote_terminal" if terminal else "pending")
            else:
                raise A2ACoordinationError(
                    "TASK_EVIDENCE_INVALID", "invalid remote transition event")
            record["updated_at"] = _now()
            updated = self._append_unlocked(record)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return updated

    def request_cancellation(
            self, work_item_id: str,
            principal_id: str) -> dict[str, Any]:
        """Persist cancellation intent before deciding whether A2A can confirm it."""
        with self._locked() as lock:
            record = self._load_unlocked(work_item_id)
            self._authorize(record, principal_id)
            if record.get("state") in TERMINAL_STATES:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return record
            now = _now()
            record["cancellation_requested"] = True
            record.setdefault("cancellation_requested_at", now)
            if record.get("dispatch_state", "not_started") == "not_started":
                record.update({
                    "state": "cancelled",
                    "cancellation_status": "confirmed_local",
                    "worker_outcome": {
                        "status": "cancelled",
                        "message": "cancelled before dispatch began",
                    },
                })
            else:
                record.update({
                    "state": "cancellation_pending",
                    "cancellation_status": "pending",
                    "worker_outcome": {
                        "status": "cancellation_pending",
                        "message": "remote cancellation has not been confirmed",
                    },
                })
            record["updated_at"] = now
            updated = self._append_unlocked(record)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return updated

    def update(
            self, work_item_id: str, principal_id: str,
            **changes: Any) -> dict[str, Any]:
        with self._locked() as lock:
            record = self._load_unlocked(work_item_id)
            self._authorize(record, principal_id)
            record.update(changes)
            record["updated_at"] = _now()
            updated = self._append_unlocked(record)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return updated

    def get(self, work_item_id: str, principal_id: str) -> dict[str, Any]:
        with self._locked(write=False) as lock:
            record = self._load_unlocked(work_item_id)
            self._authorize(record, principal_id)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return record

    @staticmethod
    def _authorize(record: Mapping[str, Any], principal_id: str) -> None:
        if record.get("principal_id") != principal_id:
            # Do not disclose another principal's task identifiers.
            raise A2ACoordinationError("TASK_NOT_FOUND", "work item does not exist")


class A2ACoordinator:
    """Authorize and record worker proposals without accepting them."""

    def __init__(
            self, policy: CoordinationPolicy, store: TaskStore,
            client: WorkerClient, *, project_root: Path,
            coordinator_id: str | None = None,
            dispatch_lease_seconds: float = 60.0):
        if (not math.isfinite(dispatch_lease_seconds)
                or dispatch_lease_seconds <= 0):
            raise ValueError("dispatch_lease_seconds must be positive")
        selected_coordinator = coordinator_id or str(uuid.uuid4())
        if not _IDENTIFIER.fullmatch(selected_coordinator):
            raise ValueError("coordinator_id is invalid")
        self.policy = policy
        self.store = store
        self.client = client
        self.project_root = project_root.resolve()
        self.coordinator_id = selected_coordinator
        self.dispatch_lease_seconds = dispatch_lease_seconds

    @contextmanager
    def _dispatch_lease(
            self, work_item_id: str, principal_id: str,
            attempt_id: str):
        """Renew dispatch ownership while this process waits on the worker."""
        stop = threading.Event()
        interval = max(0.05, self.dispatch_lease_seconds / 3)

        def heartbeat() -> None:
            while not stop.wait(interval):
                try:
                    renewed = self.store.renew_dispatch_lease(
                        work_item_id, principal_id,
                        attempt_id=attempt_id,
                        owner_id=self.coordinator_id,
                        lease_seconds=self.dispatch_lease_seconds)
                except Exception:
                    return
                if not renewed:
                    return

        thread = threading.Thread(
            target=heartbeat, name=f"a2a-lease-{work_item_id}", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=min(interval, 1.0))

    def _authorize(
            self, item: WorkItem, principal_id: str,
            worker_id: str | None) -> tuple[AuthorityGrant, WorkerProfile]:
        grant = self.policy.authorities.get(item.authority_ref)
        if grant is None or grant.principal_id != principal_id:
            raise A2ACoordinationError(
                "AUTHORITY_DENIED", "authority reference is unavailable")
        if grant.project_root != self.project_root:
            raise A2ACoordinationError(
                "AUTHORITY_DENIED", "authority belongs to another project")
        if grant.expires_at is not None and datetime.fromisoformat(
                grant.expires_at) <= datetime.now(timezone.utc):
            raise A2ACoordinationError(
                "AUTHORITY_EXPIRED", "authority reference has expired")
        candidates = [
            worker for worker in self.policy.workers.values()
            if worker.worker_id in grant.workers
            and item.workflow in worker.workflows
        ]
        if worker_id is not None:
            candidates = [
                worker for worker in candidates if worker.worker_id == worker_id]
        if item.workflow not in grant.workflows or not candidates:
            raise A2ACoordinationError(
                "AUTHORITY_DENIED", "workflow or worker is not authorized")
        worker = sorted(candidates, key=lambda value: value.worker_id)[0]
        allowed_effects = (
            set(item.requested_effects).issubset(grant.effects)
            and set(item.requested_effects).issubset(worker.effects)
        )
        if not allowed_effects:
            raise A2ACoordinationError(
                "AUTHORITY_DENIED", "requested effects exceed worker grant")
        for scope in item.allowed_paths:
            granted = any(
                _scope_contains(allowed, scope)
                for allowed in grant.allowed_paths)
            supported = any(
                _scope_contains(allowed, scope)
                for allowed in worker.allowed_paths)
            if not granted or not supported:
                raise A2ACoordinationError(
                    "AUTHORITY_DENIED", f"path scope is not granted: {scope}")
        for key, requested in item.resource_budget.items():
            ceilings = [
                limits[key]
                for limits in (grant.max_budget, worker.max_budget)
                if key in limits
            ]
            if not ceilings or requested > min(ceilings):
                raise A2ACoordinationError(
                    "BUDGET_DENIED", f"budget exceeds ceiling: {key}")
        return grant, worker

    def _effective_item(
            self, item: WorkItem, principal_id: str) -> WorkItem:
        """Apply inherited restrictions before hashing, storage, and dispatch."""
        if item.parent_work_item_id is None:
            return item
        parent_record = self.store.get(item.parent_work_item_id, principal_id)
        parent = self._item(parent_record)
        return replace(
            item,
            protected_paths=tuple(sorted(
                set(item.protected_paths) | set(parent.protected_paths))),
        )

    @staticmethod
    def _validate_result(
            item: WorkItem,
            value: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        result = dict(value)
        bound = (
            result.get("schema") == WORKER_RESULT_SCHEMA
            and result.get("work_item_id") == item.work_item_id
            and result.get("base_revision") == item.base_revision
        )
        if not bound:
            raise A2ACoordinationError(
                "WORKER_RESULT_INVALID", "worker result binding is invalid")
        patch_digest = result.get("patch_sha256")
        if patch_digest is not None and not _SHA256.fullmatch(str(patch_digest)):
            raise A2ACoordinationError(
                "WORKER_RESULT_INVALID", "invalid patch digest")
        changed = result.get("changed_files", [])
        if not isinstance(changed, list):
            raise A2ACoordinationError(
                "WORKER_RESULT_INVALID", "changed_files must be a list")
        for raw in changed:
            path = _scope(str(raw))
            allowed = _path_allowed(path, item.allowed_paths)
            protected = any(
                _path_allowed(path, (scope,))
                for scope in item.protected_paths)
            if not allowed or protected:
                raise A2ACoordinationError(
                    "WORKER_SCOPE_VIOLATION",
                    f"worker changed an unauthorized path: {path}")
        artifacts = result.get("artifacts", [])
        if not isinstance(artifacts, list):
            raise A2ACoordinationError(
                "WORKER_RESULT_INVALID", "artifacts must be a list")
        for artifact in artifacts:
            valid = (
                isinstance(artifact, dict)
                and _IDENTIFIER.fullmatch(str(artifact.get("artifact_id", "")))
                and _SHA256.fullmatch(str(artifact.get("sha256", "")))
            )
            if not valid:
                raise A2ACoordinationError(
                    "WORKER_RESULT_INVALID", "invalid artifact reference")
        return result

    def submit(
            self, item: WorkItem, principal_id: str,
            worker_id: str | None = None) -> dict[str, Any]:
        item = self._effective_item(item, principal_id)
        grant, worker = self._authorize(item, principal_id, worker_id)
        now = _now()
        record = {
            "schema": COORDINATION_RECORD_SCHEMA,
            "work_item_id": item.work_item_id,
            "request_sha256": item.request_sha256,
            "principal_id": principal_id,
            "worker_id": worker.worker_id,
            "state": "queued",
            "dispatch_state": "not_started",
            "dispatch_attempt_id": None,
            "dispatch_owner_id": None,
            "dispatch_lease_expires_at": None,
            "remote_task_id": None,
            "remote_state": None,
            "cancellation_requested": False,
            "cancellation_status": "not_requested",
            "work_item": item.as_dict(),
            "worker_result": None,
            "worker_outcome": None,
            "coordination_status": "consistent",
            "coordination_diagnostics": [],
            "coordination_diagnostic_count": 0,
            "acceptance": {"status": "pending", "claim": "NO_PROOF"},
            "authority_sha256": _digest(grant.as_dict()),
            "worker_profile_sha256": _digest(worker.as_dict()),
            "created_at": now,
            "updated_at": now,
        }
        aggregate_ceiling = {
            key: min(grant.max_budget[key], worker.max_budget[key])
            for key in set(grant.max_budget) & set(worker.max_budget)
        }
        stored, created = self.store.create(
            record, aggregate_ceiling=aggregate_ceiling)
        if not created:
            return stored
        dispatch_record, dispatch = self.store.begin_dispatch(
            item.work_item_id, principal_id,
            owner_id=self.coordinator_id,
            lease_seconds=self.dispatch_lease_seconds)
        if not dispatch:
            return dispatch_record
        attempt_id = str(dispatch_record["dispatch_attempt_id"])
        try:
            with self._dispatch_lease(
                    item.work_item_id, principal_id, attempt_id):
                observation = self.client.submit(worker, item)
        except Exception as exc:
            if isinstance(exc, A2ACoordinationError):
                code, message = exc.code, str(exc)
            else:
                code, message = "WORKER_UNAVAILABLE", str(exc)
            return self.store.transition_remote_event(
                item.work_item_id, principal_id,
                attempt_id=attempt_id, event_kind="transport_error",
                operation="submit", code=code, message=message)
        return self._apply_observation(
            item, principal_id, observation,
            attempt_id=attempt_id)

    def _apply_observation(
            self, item: WorkItem, principal_id: str,
            observation: RemoteTaskObservation, *,
            attempt_id: str,
            request_remote_cancellation: bool = True) -> dict[str, Any]:
        state = observation.state.lower().removeprefix("task_state_")
        supported = {
            "submitted", "working", "input_required", "auth_required",
            "completed", "failed", "cancelled", "rejected",
        }
        if state not in supported:
            return self.store.transition_remote_event(
                item.work_item_id, principal_id,
                attempt_id=attempt_id, event_kind="protocol_error",
                remote_task_id=observation.remote_task_id,
                remote_state=state, code="WORKER_RESULT_INVALID",
                message="unknown worker task state")
        try:
            result = self._validate_result(item, observation.result)
        except A2ACoordinationError as exc:
            return self.store.transition_remote_event(
                item.work_item_id, principal_id,
                attempt_id=attempt_id, event_kind="protocol_error",
                remote_task_id=observation.remote_task_id,
                remote_state=state, code=exc.code, message=str(exc))
        record = self.store.transition_remote_event(
            item.work_item_id, principal_id,
            attempt_id=attempt_id, event_kind="observation",
            remote_task_id=observation.remote_task_id,
            remote_state=state, worker_result=result,
            message=observation.message)
        if (request_remote_cancellation
                and record.get("cancellation_requested")
                and record.get("state") not in TERMINAL_STATES):
            return self._cancel_remote(item, principal_id, record)
        return record

    def _cancel_remote(
            self, item: WorkItem, principal_id: str,
            record: Mapping[str, Any]) -> dict[str, Any]:
        remote_task_id = record.get("remote_task_id")
        if not remote_task_id:
            return dict(record)
        worker = self.policy.workers[str(record["worker_id"])]
        try:
            observation = self.client.cancel(worker, str(remote_task_id))
        except Exception as exc:
            return self.store.transition_remote_event(
                item.work_item_id, principal_id,
                attempt_id=str(record["dispatch_attempt_id"]),
                event_kind="transport_error",
                remote_task_id=str(remote_task_id),
                operation="cancel", code="WORKER_UNAVAILABLE",
                message=str(exc))
        # A cancellation response may still report a non-terminal remote state.
        # Record that observation without recursively issuing cancellation calls.
        return self._apply_observation(
            item, principal_id, observation,
            attempt_id=str(record["dispatch_attempt_id"]),
            request_remote_cancellation=False)

    @staticmethod
    def _item(record: Mapping[str, Any]) -> WorkItem:
        return WorkItem(**{
            key: value for key, value in record["work_item"].items()
            if key != "schema"
        })

    def get(
            self, work_item_id: str, principal_id: str, *,
            refresh: bool = True) -> dict[str, Any]:
        record = self.store.get(work_item_id, principal_id)
        if not refresh or record["state"] in TERMINAL_STATES:
            return record
        worker = self.policy.workers[record["worker_id"]]
        item = self._item(record)
        if not record.get("remote_task_id"):
            reconcile = getattr(self.client, "reconcile", None)
            if not callable(reconcile):
                return record
            record, claimed = self.store.claim_reconciliation(
                work_item_id, principal_id,
                owner_id=self.coordinator_id,
                lease_seconds=self.dispatch_lease_seconds)
            if not claimed:
                return record
            attempt_id = str(record["dispatch_attempt_id"])
            try:
                observation = reconcile(worker, item)
            except Exception as exc:
                return self.store.transition_remote_event(
                    work_item_id, principal_id,
                    attempt_id=attempt_id, event_kind="transport_error",
                    operation="reconcile", code="WORKER_UNAVAILABLE",
                    message=str(exc))
            if observation is None:
                return self.store.transition_remote_event(
                    work_item_id, principal_id,
                    attempt_id=attempt_id, event_kind="transport_error",
                    operation="reconcile", code="REMOTE_TASK_NOT_OBSERVED",
                    message="the worker did not report the dispatch attempt")
            return self._apply_observation(
                item, principal_id, observation,
                attempt_id=attempt_id)
        if record.get("cancellation_requested"):
            return self._cancel_remote(item, principal_id, record)
        observation = self.client.get(worker, record["remote_task_id"])
        return self._apply_observation(
            item, principal_id, observation,
            attempt_id=str(record["dispatch_attempt_id"]))

    def artifacts(self, work_item_id: str, principal_id: str) -> dict[str, Any]:
        record = self.store.get(work_item_id, principal_id)
        result = record.get("worker_result") or {}
        return {
            "status": record["state"],
            "work_item_id": work_item_id,
            "artifacts": result.get("artifacts", []),
            "patch_sha256": result.get("patch_sha256"),
            "acceptance": record["acceptance"],
            "coordination_status": record.get("coordination_status", "consistent"),
            "coordination_diagnostics": record.get(
                "coordination_diagnostics", []),
        }

    def cancel(self, work_item_id: str, principal_id: str) -> dict[str, Any]:
        record = self.store.request_cancellation(work_item_id, principal_id)
        if (record["state"] in TERMINAL_STATES
                or not record.get("remote_task_id")):
            return record
        return self._cancel_remote(self._item(record), principal_id, record)


class OfficialA2AWorkerClient:
    """A2A 1.0 client adapter using the pinned official Python SDK."""

    def __init__(self, *, timeout_seconds: float = 30.0):
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _token(worker: WorkerProfile) -> str | None:
        if not worker.auth_token_env:
            return None
        token = os.environ.get(worker.auth_token_env)
        if not token:
            raise A2ACoordinationError(
                "WORKER_AUTH_UNAVAILABLE", "worker credential is unavailable")
        return token

    def submit(
            self, worker: WorkerProfile,
            work_item: WorkItem) -> RemoteTaskObservation:
        return self._run_sync(self._submit(worker, work_item))

    def get(
            self, worker: WorkerProfile,
            task_id: str) -> RemoteTaskObservation:
        return self._run_sync(self._get(worker, task_id, cancel=False))

    def cancel(
            self, worker: WorkerProfile,
            task_id: str) -> RemoteTaskObservation:
        return self._run_sync(self._get(worker, task_id, cancel=True))

    def reconcile(
            self, worker: WorkerProfile,
            work_item: WorkItem) -> RemoteTaskObservation | None:
        return self._run_sync(self._reconcile(worker, work_item))

    @staticmethod
    def _submission_context_id(work_item: WorkItem) -> str:
        """Stable A2A context identity for lookup after a lost submit reply."""
        return str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"formalspecgen:{work_item.request_sha256}"))

    @staticmethod
    def _run_sync(coroutine):
        """Run the SDK coroutine even when a sync MCP tool owns an event loop."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coroutine)
        result: list[Any] = []
        errors: list[BaseException] = []

        def run() -> None:
            try:
                result.append(asyncio.run(coroutine))
            except BaseException as exc:  # re-raised in the caller thread
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join()
        if errors:
            raise errors[0]
        return result[0]

    async def _client(self, worker: WorkerProfile):
        try:
            import httpx
            from a2a.client import ClientConfig, create_client
            from google.protobuf.json_format import MessageToDict
        except ImportError as exc:  # pragma: no cover - optional dependency boundary
            raise A2ACoordinationError(
                "A2A_SDK_UNAVAILABLE", "install formalspecgen[a2a]") from exc
        headers = {}
        token = self._token(worker)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        http = httpx.AsyncClient(headers=headers, timeout=self.timeout_seconds)

        def verify_card(card) -> None:
            value = MessageToDict(card, preserving_proto_field_name=True)
            if _digest(value) != worker.agent_card_sha256:
                raise A2ACoordinationError(
                    "WORKER_IDENTITY_MISMATCH",
                    "worker Agent Card digest changed")

        try:
            client = await create_client(
                worker.endpoint,
                client_config=ClientConfig(
                    streaming=False,
                    polling=False,
                    httpx_client=http,
                    supported_protocol_bindings=["JSONRPC"],
                ),
                signature_verifier=verify_card,
            )
        except Exception:
            await http.aclose()
            raise
        return client, http

    @staticmethod
    def _observation(task) -> RemoteTaskObservation:
        from a2a.helpers import get_artifact_text, get_message_text
        from a2a.types import TaskState

        state = TaskState.Name(task.status.state).lower().removeprefix(
            "task_state_")
        result = None
        for artifact in task.artifacts:
            if artifact.name != "formalspecgen-work-result":
                continue
            try:
                result = json.loads(get_artifact_text(artifact))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise A2ACoordinationError(
                    "WORKER_RESULT_INVALID",
                    "worker result artifact is not valid JSON") from exc
        message = (
            get_message_text(task.status.message)
            if task.status.HasField("message") else "")
        return RemoteTaskObservation(task.id, state, result, message)

    async def _submit(
            self, worker: WorkerProfile,
            work_item: WorkItem) -> RemoteTaskObservation:
        from a2a.helpers import new_text_message
        from a2a.types import Role, SendMessageRequest

        client, http = await self._client(worker)
        try:
            request = SendMessageRequest(message=new_text_message(
                _canonical_bytes(work_item.as_dict()).decode("utf-8"),
                context_id=self._submission_context_id(work_item),
                role=Role.ROLE_USER,
            ))
            task = None
            async for event in client.send_message(request):
                if event.HasField("task"):
                    task = event.task
            if task is None:
                raise A2ACoordinationError(
                    "WORKER_RESULT_INVALID",
                    "worker did not return an A2A task")
            return self._observation(task)
        finally:
            await client.close()
            await http.aclose()

    async def _reconcile(
            self, worker: WorkerProfile,
            work_item: WorkItem) -> RemoteTaskObservation | None:
        from a2a.types import ListTasksRequest

        client, http = await self._client(worker)
        try:
            response = await client.list_tasks(ListTasksRequest(
                context_id=self._submission_context_id(work_item),
                page_size=2, include_artifacts=True))
            if not response.tasks:
                return None
            if len(response.tasks) != 1:
                raise A2ACoordinationError(
                    "WORKER_RECONCILIATION_CONFLICT",
                    "stable submission identity resolved to multiple remote tasks")
            return self._observation(response.tasks[0])
        finally:
            await client.close()
            await http.aclose()

    async def _get(
            self, worker: WorkerProfile, task_id: str, *,
            cancel: bool) -> RemoteTaskObservation:
        from a2a.types import CancelTaskRequest, GetTaskRequest

        client, http = await self._client(worker)
        try:
            task = (
                await client.cancel_task(CancelTaskRequest(id=task_id))
                if cancel
                else await client.get_task(GetTaskRequest(id=task_id))
            )
            return self._observation(task)
        finally:
            await client.close()
            await http.aclose()


def agent_card_sha256(card: Any) -> str:
    """Return the canonical digest used by worker identity pinning."""
    try:
        from google.protobuf.json_format import MessageToDict
    except ImportError as exc:  # pragma: no cover - optional dependency boundary
        raise A2ACoordinationError(
            "A2A_SDK_UNAVAILABLE", "install formalspecgen[a2a]") from exc
    return _digest(MessageToDict(card, preserving_proto_field_name=True))


def current_git_revision(root: Path) -> str:
    """Read the current commit without starting a subprocess."""
    git = root.resolve() / ".git"
    if git.is_file():
        value = git.read_text(encoding="utf-8").strip()
        if not value.startswith("gitdir: "):
            raise A2ACoordinationError(
                "REVISION_UNAVAILABLE", "invalid .git file")
        git = (git.parent / value[8:]).resolve()
    head = (git / "HEAD").read_text(encoding="ascii").strip()
    if _GIT_REVISION.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        raise A2ACoordinationError(
            "REVISION_UNAVAILABLE", "invalid Git HEAD")
    ref = head[5:]
    ref_path = git / ref
    if ref_path.is_file():
        revision = ref_path.read_text(encoding="ascii").strip()
    else:
        revision = ""
        packed = git / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="ascii").splitlines():
                if line and not line.startswith(("#", "^")):
                    candidate, name = line.split(" ", 1)
                    if name == ref:
                        revision = candidate
                        break
    if not _GIT_REVISION.fullmatch(revision):
        raise A2ACoordinationError(
            "REVISION_UNAVAILABLE", "cannot resolve Git HEAD")
    return revision
