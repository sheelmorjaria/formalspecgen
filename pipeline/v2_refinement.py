# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared evidence binding for source-to-reviewed-V2 refinement gates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .domain_v2_evidence import verify_evidence_envelope
from .domain_v2_promotion import ReviewedDomainSpecV2
from .domain_v2_tla import render_v2_tla


class RefinementBoundaryError(ValueError):
    """A reviewed model cannot be bound to its claimed validation evidence."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def load_bound_reviewed_domain(reviewed_path: str | Path,
                               validation_path: str | Path) -> ReviewedDomainSpecV2:
    """Load a reviewed model only when every validation hash still agrees."""
    try:
        reviewed = ReviewedDomainSpecV2.model_validate_json(
            Path(reviewed_path).read_text(encoding="utf-8"))
        envelope = json.loads(Path(validation_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RefinementBoundaryError("unsupported_refinement_boundary", str(exc)) from exc
    if not verify_evidence_envelope(envelope):
        raise RefinementBoundaryError(
            "invalid_evidence_digest", "Validation evidence digest does not match")
    evidence = envelope["evidence"]
    if evidence.get("validation_status") != "VALIDATED" or evidence.get("tlc_exit_status") != 0:
        raise RefinementBoundaryError(
            "evidence_not_validated", "Evidence is not a successful V2 validation")
    if reviewed.accepted_evidence_sha256 != envelope["evidence_sha256"]:
        raise RefinementBoundaryError(
            "reviewed_evidence_mismatch", "Reviewed model is not bound to this evidence")
    if reviewed.accepted_candidate_sha256 != evidence.get("candidate_sha256"):
        raise RefinementBoundaryError(
            "candidate_evidence_mismatch", "Reviewed candidate is not bound to evidence")
    tla, _ = render_v2_tla(reviewed)
    if hashlib.sha256(tla.encode()).hexdigest() != evidence.get("generated_tla_sha256"):
        raise RefinementBoundaryError(
            "tla_serialization_mismatch", "Evidence did not validate this deterministic TLA+")
    return reviewed
