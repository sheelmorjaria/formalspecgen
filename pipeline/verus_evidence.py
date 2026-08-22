# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Anti-vacuity and exact-overlay policy for Verus evidence."""
from __future__ import annotations

from .judge_evidence import assess_proof_evidence


_BEGIN = "/* VERUS_OVERLAY_BEGIN:"
_END = "/* VERUS_OVERLAY_END:"
_REPLACE = "/* VERUS_OVERLAY_REPLACE:"
_REPLACE_END = "/* VERUS_OVERLAY_REPLACE_END */"


def erase_overlay(source: str) -> str:
    """Remove qualified Verus-only regions and restore replaced production lines."""
    output: list[str] = []
    skipping = False
    replacing = False
    for line in source.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(_BEGIN):
            skipping = True
            continue
        if stripped.startswith(_END):
            if not skipping:
                raise ValueError("overlay end without begin")
            skipping = False
            continue
        if stripped.startswith(_REPLACE):
            if skipping or replacing:
                raise ValueError("nested overlay replacement")
            payload = stripped[len(_REPLACE):-2].strip()
            indent = line[:len(line) - len(line.lstrip())]
            output.append(f"{indent}{payload}\n")
            replacing = True
            continue
        if stripped == _REPLACE_END:
            if not replacing:
                raise ValueError("replacement end without begin")
            replacing = False
            continue
        if not skipping and not replacing:
            output.append(line)
    if skipping or replacing:
        raise ValueError("unterminated overlay region")
    return "".join(output)


def assess_verus_evidence(*, verification_units: int, proof_obligations: int,
                          semantic_postconditions: int, mutation_failures: int,
                          overlay_matches: bool) -> dict[str, object]:
    """Apply the system-wide minimum anti-vacuity policy to one judge result."""
    result = assess_proof_evidence(
        verification_units=verification_units,
        proof_obligations=proof_obligations,
        semantic_postconditions=semantic_postconditions,
        mutation_failures=mutation_failures,
        artifact_matches=overlay_matches,
        refusal_prefix="VERUS",
    )
    if "VERUS_ARTIFACT_DRIFT" in result["refusals"]:
        result["refusals"].remove("VERUS_ARTIFACT_DRIFT")
        result["refusals"].append("VERUS_OVERLAY_DRIFT")
    return result
