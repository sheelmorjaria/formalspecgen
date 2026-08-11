# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Crash-conscious publication primitives for future V2 validation evidence."""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .domain_v2_evidence import build_evidence_envelope, verify_evidence_envelope


class _Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[2] = 2
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_assumption: str
    bounds: dict[str, int | list[int]]
    state_space_upper_bound: int = Field(ge=1)


class PendingEvidence(_Evidence):
    validation_status: Literal["PENDING"] = "PENDING"
    reachable_state_count: None = None
    reachable_transition_count: None = None
    tlc_exit_status: None = None


class TlcEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: str = Field(min_length=1)
    command: list[str] = Field(min_length=1)
    status: Literal["OK"] = "OK"


class ValidatedEvidence(_Evidence):
    validation_status: Literal["VALIDATED"] = "VALIDATED"
    generated_tla_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    abstraction_mode: str
    reachable_state_count: int = Field(ge=1)
    reachable_transition_count: int = Field(ge=0)
    tools: dict[Literal["tlc"], TlcEvidence]
    tlc_exit_status: Literal[0] = 0


class EvidenceEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence: ValidatedEvidence
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def digest_matches(self) -> "EvidenceEnvelope":
        if not verify_evidence_envelope(self.model_dump(mode="json")):
            raise ValueError("evidence envelope digest mismatch")
        return self


def validated_envelope(evidence: ValidatedEvidence) -> EvidenceEnvelope:
    return EvidenceEnvelope.model_validate(build_evidence_envelope(
        evidence.model_dump(mode="json")))


def write_json_atomic(destination: str | Path, value: dict, *, mode: int = 0o600) -> Path:
    """Publish JSON by fsyncing a same-directory temporary file before replacement."""
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    return path


def scrub_diagnostic(value: str) -> str:
    value = re.sub(r"(?i)\b(api[_-]?key|token|password|secret)\s*[=:]\s*\S+",
                   r"\1=<redacted>", value)
    return value[-4000:]


def publish_validation_success(path: str | Path, evidence: ValidatedEvidence) -> Path:
    return write_json_atomic(path, validated_envelope(evidence).model_dump(mode="json"))


def publish_validation_failure(path: str | Path, *, candidate_sha256: str,
                               failed_gate: str, diagnostic: str,
                               tool_provenance: dict | None = None) -> Path:
    artifact = {"schema_version": 2, "validation_status": "VALIDATION_FAILED",
                "candidate_sha256": candidate_sha256, "failed_gate": failed_gate,
                "diagnostic": scrub_diagnostic(diagnostic),
                "tool_provenance": tool_provenance or {}}
    return write_json_atomic(path, artifact)
