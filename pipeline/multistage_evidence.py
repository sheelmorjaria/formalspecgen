# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Reusable immutable publication for workflows with several judged stages."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from .lifecycle import EvidenceClaim, PipelineState, RunLedger


MULTISTAGE_EVIDENCE_SCHEMA = "formalspecgen-multistage-evidence-v1"


def publish_multistage_evidence(
        root: Path, *, workflow: str, status: str, claim: str,
        request: Mapping[str, Any], admission: Mapping[str, Any] | None,
        inputs: Mapping[str, Any], stages: Sequence[Mapping[str, Any]],
        semantic_bindings: Mapping[str, Any],
        claim_limits: Mapping[str, Any]) -> dict[str, Any]:
    """Commit one write-once manifest that binds all inputs and observations."""
    run_root = root / uuid.uuid4().hex
    ledger = RunLedger(run_root)
    stage_values = [dict(item) for item in stages]
    evidence_claim = _ledger_claim(claim)
    ledger.record(
        PipelineState.PROOF, status, claim=evidence_claim,
        details={
            "schema": MULTISTAGE_EVIDENCE_SCHEMA,
            "workflow": workflow,
            "workflow_request": dict(request),
            "mcp_admission": dict(admission) if admission is not None else None,
            "stage_count": len(stage_values),
        },
        evidence={
            "inputs": dict(inputs),
            "stages": stage_values,
            "semantic_bindings": dict(semantic_bindings),
            "claim_limits": dict(claim_limits),
            "stage_output_sha256": [
                hashlib.sha256(str(item.get("output", "")).encode("utf-8")).hexdigest()
                for item in stage_values
            ],
        },
    )
    terminal = {
        "schema": MULTISTAGE_EVIDENCE_SCHEMA,
        "workflow": workflow,
        "final_status": status,
        "claim": claim,
        "request_satisfied": status == "VERIFIED" and claim != "NO_PROOF",
        "workflow_request": dict(request),
        "mcp_admission": dict(admission) if admission is not None else None,
        "inputs": dict(inputs),
        "semantic_bindings": dict(semantic_bindings),
        "claim_limits": dict(claim_limits),
        "execution_stages": stage_values,
    }
    manifest = ledger.commit(terminal)
    encoded = manifest.read_bytes()
    return {
        "run_id": ledger.run_id,
        "manifest_path": str(manifest),
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "manifest_size": len(encoded),
        "publication_status": "COMMITTED",
        "schema": MULTISTAGE_EVIDENCE_SCHEMA,
    }


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ledger_claim(claim: str) -> EvidenceClaim:
    if claim == "BOUNDED_REFACTOR_CONTRACT_PRESERVED":
        return EvidenceClaim.BOUNDED_CPP_PROOF
    if claim in {
            "REFACTOR_CONTRACT_PRESERVED",
            "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"}:
        return EvidenceClaim.DEDUCTIVE_PROOF
    return EvidenceClaim.NO_PROOF
