# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Shared six-state lifecycle, evidence ledger, hashes, and proof provenance."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
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
    """Write one immutable JSON evidence artifact for every lifecycle transition."""

    def __init__(self, root: Path, on_event: Callable[[dict], None] | None = None):
        self.root = root
        self.evidence_dir = root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.on_event = on_event
        self.transitions: list[PipelineTransition] = []

    def record(self, state: PipelineState, status: str, *, claim: EvidenceClaim,
               details: dict[str, Any] | None = None,
               evidence: dict[str, Any] | None = None) -> PipelineTransition:
        sequence = len(self.transitions) + 1
        path = self.evidence_dir / f"{sequence:03d}-{state.value.lower()}.json"
        payload = {"sequence": sequence, "state": state.value, "status": status,
                   "claim": claim.value, "details": details or {},
                   "evidence": evidence or {}}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        transition = PipelineTransition(sequence, state.value, status,
            datetime.now(timezone.utc).isoformat(), claim.value, str(path), details or {})
        self.transitions.append(transition)
        if self.on_event:
            self.on_event({"type": "pipeline_transition", **asdict(transition)})
        return transition
