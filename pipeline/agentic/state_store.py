# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Append-only operational state and no-replace agent review publication."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .contracts import (
    AGENT_RUN_SCHEMA,
    AgentGoal,
    AgentRunError,
    canonical_bytes,
    digest,
)


AGENT_EVENT_SCHEMA = "formalspecgen-agent-run-event-v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentRunStore:
    """Principal-scoped, hash-chained run state outside the agent workspace."""

    def __init__(self, root: Path, *, create: bool = True):
        self.root = root.resolve()
        self.runs = self.root / "runs"
        if create:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.runs.mkdir(exist_ok=True, mode=0o700)
        elif not self.runs.is_dir():
            raise AgentRunError("RUN_STORE_UNAVAILABLE", "agent run store is unavailable")
        self.lock_path = self.root / ".lock"

    @contextmanager
    def _locked(self, *, write: bool) -> Iterator[None]:
        mode = "a+b" if write else "rb"
        try:
            handle = self.lock_path.open(mode)
        except FileNotFoundError as exc:
            raise AgentRunError(
                "RUN_STORE_UNAVAILABLE", "agent run store is unavailable") from exc
        with handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            yield

    def _directory(self, run_id: str) -> Path:
        # AgentGoal performs the canonical identifier validation.  This local
        # check prevents path construction from untrusted retrieval input.
        if not run_id or any(mark in run_id for mark in "/\\") or run_id in {".", ".."}:
            raise AgentRunError("INVALID_GOAL", "invalid run_id")
        return self.runs / run_id

    @staticmethod
    def _events(directory: Path) -> list[Path]:
        return sorted(directory.glob("[0-9][0-9][0-9][0-9][0-9][0-9].json"))

    def _load_unlocked(self, run_id: str) -> dict[str, Any]:
        events = self._events(self._directory(run_id))
        if not events:
            raise AgentRunError("RUN_NOT_FOUND", "agent run does not exist")
        previous = None
        record: Any = None
        for sequence, path in enumerate(events, start=1):
            try:
                event = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise AgentRunError("RUN_EVIDENCE_INVALID", str(exc)) from exc
            observed = event.pop("sha256", None)
            if (event.get("schema") != AGENT_EVENT_SCHEMA
                    or event.get("sequence") != sequence
                    or event.get("previous_sha256") != previous
                    or observed != digest(event)):
                raise AgentRunError("RUN_EVIDENCE_INVALID", "agent event chain is invalid")
            previous = observed
            record = event.get("record")
        if not isinstance(record, dict) or record.get("schema") != AGENT_RUN_SCHEMA:
            raise AgentRunError("RUN_EVIDENCE_INVALID", "agent run record is invalid")
        return record

    def _append_unlocked(self, record: Mapping[str, Any]) -> dict[str, Any]:
        directory = self._directory(str(record["run_id"]))
        directory.mkdir(mode=0o700, exist_ok=True)
        events = self._events(directory)
        previous = None
        if events:
            previous = json.loads(events[-1].read_text(encoding="utf-8"))["sha256"]
        event = {
            "schema": AGENT_EVENT_SCHEMA,
            "sequence": len(events) + 1,
            "previous_sha256": previous,
            "record": dict(record),
            "recorded_at": _now(),
        }
        event["sha256"] = digest(event)
        destination = directory / f"{len(events) + 1:06d}.json"
        descriptor, name = tempfile.mkstemp(prefix=".event-", dir=directory)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(canonical_bytes(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, destination)
            self._fsync(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return dict(record)

    @staticmethod
    def _authorize(record: Mapping[str, Any], principal_id: str) -> None:
        if record.get("principal_id") != principal_id:
            raise AgentRunError("RUN_ACCESS_DENIED", "agent run belongs to another principal")

    def _validate_review(self, record: Mapping[str, Any]) -> None:
        receipt = record.get("review")
        if receipt is None:
            return
        expected = self._directory(str(record["run_id"])) / "review.json"
        path = Path(str(receipt.get("path", "")))
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise AgentRunError("REVIEW_EVIDENCE_INVALID", str(exc)) from exc
        if (path.is_symlink()
                or path.absolute() != expected.absolute()
                or receipt.get("status") != "COMMITTED"
                or receipt.get("size") != len(content)
                or receipt.get("sha256") != hashlib.sha256(content).hexdigest()):
            raise AgentRunError(
                "REVIEW_EVIDENCE_INVALID", "terminal agent review integrity failed")

    def create(self, goal: AgentGoal, principal_id: str) -> tuple[dict[str, Any], bool]:
        if not principal_id.strip():
            raise AgentRunError("RUN_ACCESS_DENIED", "agent principal is required")
        record = {
            "schema": AGENT_RUN_SCHEMA,
            "run_id": goal.run_id,
            "principal_id": principal_id,
            "request_sha256": goal.request_sha256,
            "goal": goal.as_dict(),
            "state": "planned",
            "active_action": None,
            "actions": [],
            "failure_count": 0,
            "cancel_requested": False,
            "unresolved_findings": [],
            "review": None,
            "created_at": _now(),
            "updated_at": _now(),
        }
        with self._locked(write=True):
            try:
                existing = self._load_unlocked(goal.run_id)
            except AgentRunError as exc:
                if exc.code != "RUN_NOT_FOUND":
                    raise
            else:
                self._authorize(existing, principal_id)
                self._validate_review(existing)
                if existing.get("request_sha256") != goal.request_sha256:
                    raise AgentRunError(
                        "IDEMPOTENCY_CONFLICT",
                        "run_id is already bound to a different goal")
                return existing, False
            return self._append_unlocked(record), True

    def get(self, run_id: str, principal_id: str) -> dict[str, Any]:
        with self._locked(write=False):
            record = self._load_unlocked(run_id)
            self._authorize(record, principal_id)
            self._validate_review(record)
            return record

    def update(
            self, run_id: str, principal_id: str,
            mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        with self._locked(write=True):
            record = self._load_unlocked(run_id)
            self._authorize(record, principal_id)
            self._validate_review(record)
            mutate(record)
            record["updated_at"] = _now()
            return self._append_unlocked(record)

    def publish_review(
            self, run_id: str, principal_id: str,
            review: Mapping[str, Any]) -> dict[str, Any]:
        with self._locked(write=True):
            record = self._load_unlocked(run_id)
            self._authorize(record, principal_id)
            directory = self._directory(run_id)
            encoded = json.dumps(
                review, indent=2, sort_keys=True, ensure_ascii=False,
                default=str,
            ).encode("utf-8")
            destination = directory / "review.json"
            descriptor, name = tempfile.mkstemp(prefix=".review-", dir=directory)
            temporary = Path(name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    os.link(temporary, destination)
                except FileExistsError:
                    if destination.read_bytes() != encoded:
                        raise AgentRunError(
                            "REVIEW_ALREADY_PUBLISHED",
                            "a different terminal review is already published")
                self._fsync(directory)
            finally:
                temporary.unlink(missing_ok=True)
            return {
                "status": "COMMITTED",
                "path": str(destination),
                "size": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }

    @staticmethod
    def _fsync(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
