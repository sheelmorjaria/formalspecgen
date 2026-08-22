# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only exact-hash promotion for the M89 authority algebra."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .capability_authority_model import CapabilityAuthorityModel


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


def promote_capability_authority_model(
        project_root: str | Path, *, accept_candidate_sha256: str) -> dict[str, Any]:
    """Freeze reviewed algebra intent without treating review as proof."""
    root = Path(project_root).resolve()
    directory = root / "examples/formalkernel/kernel"
    candidate = directory / "m89_capability_authority.candidate.json"
    reviewed = directory / "m89_capability_authority.reviewed.json"
    digest = _sha256(candidate)
    if digest != accept_candidate_sha256:
        raise ValueError("CRITICAL: capability-authority candidate hash mismatch")
    model = CapabilityAuthorityModel.model_validate_json(candidate.read_text())
    value = {
        **model.model_dump(mode="json"),
        "status": "REVIEWED_CAPABILITY_AUTHORITY_MODEL",
        "review_status": "reviewed",
        "accepted_candidate_sha256": digest,
    }
    _write_json_atomic(reviewed, value)
    return {
        "status": "CAPABILITY_AUTHORITY_MODEL_PROMOTED",
        "claim": "NO_PROOF",
        "accepted_candidate_sha256": digest,
        "reviewed_model": reviewed.relative_to(root).as_posix(),
        "reviewed_model_sha256": _sha256(reviewed),
    }
