# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Pure, exact-context applicability decisions; no approval or proof authority."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping
import re

from .domain_v2_evidence import canonical_sha256


APPLICABILITY_SCHEMA = "formalspecgen-evidence-applicability-v1"


@dataclass(frozen=True)
class ApplicabilityDecision:
    applicable: bool
    reasons: tuple[str, ...]
    evidence_sha256: str
    expected_context_sha256: str
    recorded_context_sha256: str | None

    def as_dict(self) -> dict:
        return {"schema": APPLICABILITY_SCHEMA, **asdict(self),
                "decision": "APPLICABLE" if self.applicable else "REVALIDATE",
                "human_approval_required": True, "authenticity_established": False}


def evaluate_evidence_applicability(
        recorded: Mapping[str, Any] | None, expected: Mapping[str, Any], *,
        evidence_sha256: str) -> ApplicabilityDecision:
    """Compare caller-owned expectations with integrity-checked recorded bindings.

    Consumers must validate evidence integrity first and supply expectations
    independently of the evidence. Equality is exact JSON equality (including
    types), not a claim that a weaker configuration is sufficient.
    """
    if not isinstance(expected, Mapping) or (recorded is not None and not isinstance(recorded, Mapping)):
        raise ValueError("applicability contexts must be mappings")
    if not isinstance(evidence_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence_sha256):
        raise ValueError("applicability requires a full evidence digest")
    expected = dict(expected)
    reasons = []
    if not expected:
        reasons.append("EXPECTED_CONTEXT_EMPTY")
    if recorded is None:
        reasons.append("CONTEXT_NOT_RECORDED")
    else:
        recorded = dict(recorded)
        for key in sorted(set(recorded) | set(expected)):
            if key not in recorded:
                reasons.append(f"MISSING:{key}")
            elif key not in expected:
                reasons.append(f"UNEXPECTED:{key}")
            elif canonical_sha256(recorded[key]) != canonical_sha256(expected[key]):
                reasons.append(f"MISMATCH:{key}")
    return ApplicabilityDecision(not reasons, tuple(reasons), evidence_sha256,
        canonical_sha256(expected), canonical_sha256(recorded) if recorded is not None else None)
