# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only, hash-bound promotion of the M88 information-flow scope."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .hyperproperty_evidence import HyperpropertyEvidence


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def promote_information_flow_scope(
    project_root: str | Path, *, accept_candidate_sha256: str,
) -> dict[str, Any]:
    """Freeze a reviewed scope without minting a noninterference claim."""
    root = Path(project_root).resolve()
    directory = root / "examples/formalkernel/kernel"
    candidate_path = directory / "m88_information_flow_scope.candidate.json"
    reviewed_path = directory / "m88_information_flow_scope.reviewed.json"
    candidate_hash = _sha256(candidate_path)
    if accept_candidate_sha256 != candidate_hash:
        raise ValueError("CRITICAL: information-flow scope candidate hash mismatch")
    raw = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate = HyperpropertyEvidence.model_validate(raw)
    if candidate.scope_review_status != "candidate" or candidate.claim != "NO_PROOF":
        raise ValueError("only an unproved candidate scope may be promoted")
    for relative, digest in candidate.artifact_sha256.items():
        if _sha256(root / relative) != digest:
            raise ValueError(f"scope dependency hash mismatch: {relative}")
    reviewed = {
        "schema_version": 1,
        "lane": "M88.2a_reviewed_information_flow_scope",
        "status": "REVIEWED_HYPERPROPERTY_SCOPE",
        "claim": "NO_PROOF",
        "accepted_candidate_sha256": candidate_hash,
        "scope_review_status": "reviewed",
        "scope": candidate.scope.model_dump(mode="json"),
        "artifact_sha256": candidate.artifact_sha256,
        "two_run_judgment_executed": False,
        "confidentiality_mutation_rejected": False,
        "trusted_assumptions": candidate.trusted_assumptions,
        "forbidden_claims": candidate.forbidden_claims,
    }
    _write_json_atomic(reviewed_path, reviewed)
    return {
        "status": "INFORMATION_FLOW_SCOPE_PROMOTED",
        "claim": "NO_PROOF",
        "accepted_candidate_sha256": candidate_hash,
        "reviewed_scope": reviewed_path.relative_to(root).as_posix(),
        "reviewed_scope_sha256": _sha256(reviewed_path),
    }
