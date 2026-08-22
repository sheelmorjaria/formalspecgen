# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only exact-hash promotion for the M88.4 release policy."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .declassification_policy import DeclassificationPolicy


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


def promote_declassification_policy(
        project_root: str | Path, *, accept_candidate_sha256: str) -> dict[str, Any]:
    """Freeze policy intent; promotion alone never proves release correctness."""
    root = Path(project_root).resolve()
    directory = root / "examples/formalkernel/kernel"
    candidate_path = directory / "m88_declassification.candidate.json"
    reviewed_path = directory / "m88_declassification.reviewed.json"
    candidate_hash = _sha256(candidate_path)
    if candidate_hash != accept_candidate_sha256:
        raise ValueError("CRITICAL: declassification candidate hash mismatch")
    policy = DeclassificationPolicy.model_validate_json(candidate_path.read_text())
    scope = directory / "m88_information_flow_scope.reviewed.json"
    trace = directory / "m88_information_flow.trace.validation.json"
    if _sha256(scope) != policy.information_flow_scope_sha256:
        raise ValueError("reviewed information-flow scope hash mismatch")
    if _sha256(trace) != policy.trace_evidence_sha256:
        raise ValueError("trace evidence hash mismatch")
    reviewed = {
        **policy.model_dump(mode="json"),
        "status": "REVIEWED_DECLASSIFICATION_POLICY",
        "review_status": "reviewed",
        "accepted_candidate_sha256": candidate_hash,
    }
    _write_json_atomic(reviewed_path, reviewed)
    return {
        "status": "DECLASSIFICATION_POLICY_PROMOTED",
        "claim": "NO_PROOF",
        "accepted_candidate_sha256": candidate_hash,
        "reviewed_policy": reviewed_path.relative_to(root).as_posix(),
        "reviewed_policy_sha256": _sha256(reviewed_path),
    }
