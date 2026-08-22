# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""System-wide anti-vacuity policy for proof-judge evidence."""
from __future__ import annotations

from typing import Any


def assess_proof_evidence(*, verification_units: int, proof_obligations: int,
                          semantic_postconditions: int, mutation_failures: int,
                          artifact_matches: bool, refusal_prefix: str) -> dict[str, Any]:
    """Refuse a successful judge exit that lacks semantic proof activity."""
    refusals = []
    if not artifact_matches:
        refusals.append(f"{refusal_prefix}_ARTIFACT_DRIFT")
    if verification_units <= 0 or proof_obligations <= 0:
        refusals.append(f"{refusal_prefix}_ZERO_OBLIGATIONS")
    if semantic_postconditions <= 0:
        refusals.append(f"{refusal_prefix}_SPEC_VACUOUS")
    if mutation_failures <= 0:
        refusals.append(f"{refusal_prefix}_MUTATION_SURVIVED")
    return {
        "status": "QUALIFIED" if not refusals else "NO_PROOF",
        "claim": "NO_PROOF",
        "refusals": refusals,
        "counts": {
            "verification_units": verification_units,
            "proof_obligations": proof_obligations,
            "semantic_postconditions": semantic_postconditions,
            "mutation_failures": mutation_failures,
        },
    }
