# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Authoritative evidence-to-claim decisions for verifier adapters.

Backends report observations.  This module alone decides whether those
observations satisfy a verification request and which claim they justify.
Process completion is deliberately kept separate from proof success.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .verify import classify, has_dropped_vc


_PROOF_CLAIM = {
    "openjml": "DEDUCTIVE_PROOF",
    "frama-c": "DEDUCTIVE_PROOF",
    "prusti": "DEDUCTIVE_PROOF",
    "kani": "BOUNDED_EVIDENCE",
    "esbmc": "BOUNDED_CPP_PROOF",
}
_PROOF_STATUSES = {"VERIFIED"}
_NON_PROOF_SUCCESS = {
    "parse": {"VERIFIED", "PARSED"},
    "check": {"VERIFIED", "STATIC_CHECKED", "RUST_CHECKED", "C_CHECKED"},
    "compile": {"COMPILED", "STATIC_CHECKED", "RUST_CHECKED", "C_CHECKED"},
}


def decide_verification(*, tool: str, mode: str, exit_code: int,
                        output: str = "", status: str | None = None,
                        claim: str | None = None,
                        proved_obligations: int | None = None,
                        total_obligations: int | None = None,
                        dropped_obligations: bool | None = None) -> dict[str, Any]:
    """Return a normalized, fail-closed verification decision.

    ``exit_code`` says whether the tool process completed.  A proof request is
    satisfied only when the semantic status, obligation accounting, and
    dropped-obligation checks also support the claim.
    """
    normalized_tool = tool.strip().lower()
    normalized_mode = mode.strip().lower()
    tool_completed = exit_code == 0
    semantic_status = status or classify(exit_code)
    obligations_complete = True
    if total_obligations is not None or proved_obligations is not None:
        obligations_complete = (
            total_obligations is not None
            and proved_obligations is not None
            and total_obligations > 0
            and proved_obligations == total_obligations
        )
    dropped = (has_dropped_vc(output) if dropped_obligations is None
               and normalized_tool == "openjml" else bool(dropped_obligations))

    if normalized_mode == "esc":
        if dropped and semantic_status == "VERIFIED":
            semantic_status = "VACUOUS_VERIFIED"
        proof_established = (
            tool_completed
            and semantic_status in _PROOF_STATUSES
            and obligations_complete
            and not dropped
            and normalized_tool in _PROOF_CLAIM
        )
        decided_claim = _PROOF_CLAIM[normalized_tool] if proof_established else "NO_PROOF"
        request_satisfied = proof_established
    else:
        request_satisfied = (
            tool_completed
            and semantic_status in _NON_PROOF_SUCCESS.get(normalized_mode, set())
        )
        decided_claim = "STATIC_CHECK" if request_satisfied and normalized_mode in {
            "check", "compile"
        } else "NO_PROOF"

    # A backend may supply a narrower non-proof label, but it may never use a
    # successful process exit to strengthen the centrally derived decision.
    if not request_satisfied:
        decided_claim = "NO_PROOF"
    elif claim and claim == "NO_PROOF" and normalized_mode == "esc":
        decided_claim = "NO_PROOF"
        request_satisfied = False

    return {
        "tool": normalized_tool,
        "tool_exit_code": int(exit_code),
        "tool_completed": tool_completed,
        "verification": semantic_status,
        "status": semantic_status,
        "claim": decided_claim,
        "request_satisfied": request_satisfied,
        "dropped_obligations": dropped,
        "obligations_complete": obligations_complete,
    }


def decide_result(result: Mapping[str, Any], *, tool: str, mode: str) -> dict[str, Any]:
    """Normalize an existing backend result through the same claim policy."""
    output = str(result.get("output") or result.get("message") or "")
    decision = decide_verification(
        tool=tool,
        mode=mode,
        exit_code=int(result.get("exit_code", 1)),
        output=output,
        status=str(result.get("status")) if result.get("status") is not None else None,
        claim=str(result.get("claim")) if result.get("claim") is not None else None,
        proved_obligations=_optional_int(result.get("proved_goals")),
        total_obligations=_optional_int(result.get("total_goals")),
    )
    return {**result, **decision}


def _optional_int(value: Any) -> int | None:
    return int(value) if value is not None else None
