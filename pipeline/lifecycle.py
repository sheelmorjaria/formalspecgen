# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Shared six-state lifecycle, evidence ledger, hashes, and proof provenance."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable


class PipelineState(str, Enum):
    REQUIREMENTS = "REQUIREMENTS"
    CONTRACT = "CONTRACT"
    CANDIDATE = "CANDIDATE"
    CHEAP_GATES = "CHEAP_GATES"
    PROOF = "PROOF"
    REVIEW_AND_MEASURE = "REVIEW_AND_MEASURE"


class EvidenceClaim(str, Enum):
    TRANSFORMATION = "TRANSFORMATION"
    STATIC_CHECK = "STATIC_CHECK"
    DEDUCTIVE_PROOF = "DEDUCTIVE_PROOF"
    COUNTEREXAMPLE_EVIDENCE = "COUNTEREXAMPLE_EVIDENCE"
    RUNTIME_SAMPLE = "RUNTIME_SAMPLE"
    BOUNDED_ARCHITECTURE_EVIDENCE = "BOUNDED_ARCHITECTURE_EVIDENCE"
    NO_PROOF = "NO_PROOF"


@dataclass
class GateRecord:
    name: str
    order: int
    status: str
    reason: str = ""
    evidence_path: str = ""


@dataclass
class PipelineTransition:
    sequence: int
    state: str
    status: str
    timestamp: str
    claim: str
    evidence_path: str
    details: dict[str, Any] = field(default_factory=dict)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_diagnostic(value: str) -> str:
    value = re.sub(r"(?:[A-Za-z]:)?[/\\][^\s:]+", "<path>", value or "")
    value = re.sub(r"\bline\s+\d+\b", "line <n>", value, flags=re.I)
    return re.sub(r"\s+", " ", value).strip().lower()[:500]


def failure_fingerprint(backend: str, category: str, method: str | None,
                        line: int, diagnostic: str) -> str:
    canonical = json.dumps({"backend": backend, "category": category,
        "method": method or "", "line": int(line),
        "diagnostic": normalize_diagnostic(diagnostic)}, sort_keys=True)
    return sha256_text(canonical)[:20]


def command_version(command: list[str]) -> str:
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=5)
        text = ((process.stdout or "") + (process.stderr or "")).strip()
        return text.splitlines()[0][:300] if text else f"exit {process.returncode}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"


class RunLedger:
    """Publish append-only transition artifacts and a terminal manifest."""

    def __init__(self, root: Path, on_event: Callable[[dict], None] | None = None):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = root / "evidence"
        self.evidence_dir.mkdir(exist_ok=False)
        self.staging_dir = self.evidence_dir / ".staging"
        self.staging_dir.mkdir()
        self.on_event = on_event
        self.run_id = uuid.uuid4().hex
        self.transitions: list[PipelineTransition] = []
        self.artifacts: list[dict[str, Any]] = []
        self.committed = False
        _path, digest, size = self._publish_json("run.json", {
            "schema": "formalspecgen-run-v1", "run_id": self.run_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "publication_guarantee": "application-write-once",
        })
        self.artifacts.append({"path": "run.json", "sha256": digest, "size": size})

    def record(self, state: PipelineState, status: str, *, claim: EvidenceClaim,
               details: dict[str, Any] | None = None,
               evidence: dict[str, Any] | None = None) -> PipelineTransition:
        if self.committed:
            raise RuntimeError("cannot append evidence after terminal manifest publication")
        sequence = len(self.transitions) + 1
        name = f"{sequence:03d}-{state.value.lower()}.json"
        payload = {"sequence": sequence, "state": state.value, "status": status,
                   "claim": claim.value, "details": details or {},
                   "evidence": evidence or {}, "run_id": self.run_id,
                   "recorded_at": datetime.now(timezone.utc).isoformat(),
                   "previous_artifact_sha256": (
                       self.artifacts[-1]["sha256"] if self.artifacts else None)}
        path, digest, size = self._publish_json(name, payload)
        self.artifacts.append({"path": name, "sha256": digest, "size": size})
        transition = PipelineTransition(sequence, state.value, status,
            datetime.now(timezone.utc).isoformat(), claim.value, str(path), details or {})
        self.transitions.append(transition)
        if self.on_event:
            self.on_event({"type": "pipeline_transition", **asdict(transition)})
        return transition

    def commit(self, terminal: dict[str, Any]) -> Path:
        """Publish the no-replace terminal manifest after validating artifacts."""
        if self.committed:
            raise RuntimeError("evidence run is already committed")
        validation = self._validate_artifacts(self.evidence_dir, self.artifacts)
        if validation:
            raise RuntimeError(validation)
        manifest = {
            "schema": "formalspecgen-evidence-manifest-v1",
            "run_id": self.run_id,
            "committed_at": datetime.now(timezone.utc).isoformat(),
            "publication_guarantee": "application-write-once",
            "artifacts": list(self.artifacts),
            "terminal": terminal,
        }
        path, _digest, _size = self._publish_json("manifest.json", manifest)
        self.committed = True
        try:
            self.staging_dir.rmdir()
        except OSError:
            pass
        return path

    def _publish_json(self, name: str, payload: dict[str, Any]) -> tuple[Path, str, int]:
        encoded = json.dumps(
            payload, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
        staged = self.staging_dir / f"{uuid.uuid4().hex}.tmp"
        with staged.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        json.loads(staged.read_text(encoding="utf-8"))
        destination = self.evidence_dir / name
        try:
            os.link(staged, destination)
        finally:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
        directory_fd = os.open(self.evidence_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return destination, hashlib.sha256(encoded).hexdigest(), len(encoded)

    @staticmethod
    def _validate_artifacts(root: Path, artifacts: list[dict[str, Any]]) -> str:
        if not isinstance(artifacts, list) or not artifacts:
            return "evidence manifest has no artifact inventory"
        seen = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict) or not {
                    "path", "size", "sha256"}.issubset(artifact):
                return "malformed evidence artifact record"
            relative = Path(str(artifact.get("path", "")))
            if relative.is_absolute() or len(relative.parts) != 1 or relative.name != str(relative):
                return f"invalid evidence artifact path: {relative}"
            if relative.name in seen:
                return f"duplicate evidence artifact path: {relative}"
            seen.add(relative.name)
            path = root / relative
            try:
                content = path.read_bytes()
            except OSError as exc:
                return f"evidence artifact unavailable: {exc}"
            if not isinstance(artifact["size"], int) or artifact["size"] < 0 or \
                    not re.fullmatch(r"[0-9a-f]{64}", str(artifact["sha256"])) or \
                    len(content) != artifact["size"] or \
                    hashlib.sha256(content).hexdigest() != artifact["sha256"]:
                return f"evidence artifact integrity failure: {artifact['path']}"
        return ""

    @classmethod
    def validate(cls, root: Path) -> dict[str, Any]:
        """Validate a committed run without trusting mutable convenience files."""
        evidence_dir = root / "evidence"
        manifest_path = evidence_dir / "manifest.json"
        if not manifest_path.is_file():
            return {"status": "INCOMPLETE", "valid": False,
                    "message": "terminal evidence manifest is absent"}
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"status": "INVALID", "valid": False, "message": str(exc)}
        if not isinstance(manifest, dict) or \
                manifest.get("schema") != "formalspecgen-evidence-manifest-v1" or \
                not isinstance(manifest.get("run_id"), str) or \
                not isinstance(manifest.get("terminal"), dict):
            return {"status": "INVALID", "valid": False,
                    "message": "terminal evidence manifest schema is invalid"}
        error = cls._validate_artifacts(evidence_dir, manifest.get("artifacts", []))
        if error:
            return {"status": "INVALID", "valid": False, "message": error}
        previous = None
        for index, artifact in enumerate(manifest["artifacts"]):
            try:
                payload = json.loads(
                    (evidence_dir / artifact["path"]).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                return {"status": "INVALID", "valid": False, "message": str(exc)}
            if not isinstance(payload, dict):
                return {"status": "INVALID", "valid": False,
                        "message": "evidence artifact payload is not an object"}
            if payload.get("run_id") != manifest["run_id"]:
                return {"status": "INVALID", "valid": False,
                        "message": "evidence artifact run identity mismatch"}
            if index == 0:
                if artifact["path"] != "run.json" or \
                        payload.get("schema") != "formalspecgen-run-v1":
                    return {"status": "INVALID", "valid": False,
                            "message": "run identity artifact is missing or invalid"}
            elif payload.get("previous_artifact_sha256") != previous:
                return {"status": "INVALID", "valid": False,
                        "message": "evidence artifact hash chain is invalid"}
            previous = artifact["sha256"]
        return {"status": "VALID", "valid": True, "run_id": manifest.get("run_id"),
                "terminal": manifest.get("terminal", {})}
