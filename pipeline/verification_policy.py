# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Authoritative evidence-to-claim decisions for verifier adapters.

Backends report observations.  This module alone decides whether those
observations satisfy a verification request and which claim they justify.
Process completion is deliberately kept separate from proof success.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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


@dataclass(frozen=True)
class BackendObservations:
    """Raw or previously normalized observations accepted by the policy."""

    tool: str
    mode: str
    exit_code: int
    output: str = ""
    status: str | None = None
    claim: str | None = None
    proved_obligations: int | None = None
    total_obligations: int | None = None
    dropped_obligations: bool | None = None
    obligations_complete: bool | None = None
    request_satisfied: bool | None = None
    tool_completed: bool | None = None
    evidence_consistent: bool | None = None


@dataclass(frozen=True)
class VerificationDecision:
    """Normalized assurance decision emitted by the policy boundary."""

    tool: str
    mode: str
    tool_exit_code: int
    tool_completed: bool
    verification: str
    claim: str
    request_satisfied: bool
    dropped_obligations: bool
    obligations_complete: bool | None
    evidence_consistent: bool
    contradictions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "mode": self.mode,
            "tool_exit_code": self.tool_exit_code,
            "tool_completed": self.tool_completed,
            "verification": self.verification,
            "status": self.verification,
            "claim": self.claim,
            "request_satisfied": self.request_satisfied,
            "dropped_obligations": self.dropped_obligations,
            "obligations_complete": self.obligations_complete,
            "evidence_consistent": self.evidence_consistent,
            "contradictions": list(self.contradictions),
        }


def decide_verification(*, tool: str, mode: str, exit_code: int,
                        output: str = "", status: str | None = None,
                        claim: str | None = None,
                        proved_obligations: int | None = None,
                        total_obligations: int | None = None,
                        dropped_obligations: bool | None = None,
                        obligations_complete: bool | None = None,
                        prior_request_satisfied: bool | None = None,
                        prior_tool_completed: bool | None = None,
                        prior_evidence_consistent: bool | None = None) -> dict[str, Any]:
    """Return a normalized, fail-closed verification decision.

    ``exit_code`` says whether the tool process completed.  A proof request is
    satisfied only when the semantic status, obligation accounting, and
    dropped-obligation checks also support the claim.
    """
    observations = BackendObservations(
        tool=tool.strip().lower(), mode=mode.strip().lower(), exit_code=int(exit_code),
        output=output, status=status, claim=claim,
        proved_obligations=proved_obligations, total_obligations=total_obligations,
        dropped_obligations=dropped_obligations,
        obligations_complete=obligations_complete,
        request_satisfied=prior_request_satisfied,
        tool_completed=prior_tool_completed,
        evidence_consistent=prior_evidence_consistent,
    )
    normalized_tool = observations.tool
    normalized_mode = observations.mode
    contradictions: list[str] = []

    exit_completed = observations.exit_code == 0
    tool_completed = exit_completed and observations.tool_completed is not False
    if observations.tool_completed is True and not exit_completed:
        contradictions.append("tool_completed conflicts with tool_exit_code")
    semantic_status = observations.status or classify(observations.exit_code)

    counted_complete: bool | None = None
    if total_obligations is not None or proved_obligations is not None:
        counted_complete = (
            total_obligations is not None
            and proved_obligations is not None
            and total_obligations > 0
            and proved_obligations == total_obligations
        )
    if obligations_complete is False:
        decided_obligations_complete: bool | None = False
    elif counted_complete is not None:
        decided_obligations_complete = counted_complete
        if obligations_complete is True and not counted_complete:
            contradictions.append("obligations_complete conflicts with obligation counts")
    else:
        decided_obligations_complete = obligations_complete

    marker_dropped = normalized_tool == "openjml" and has_dropped_vc(output)
    dropped = marker_dropped or dropped_obligations is True
    if marker_dropped and dropped_obligations is False:
        contradictions.append("dropped_obligations conflicts with verifier output")
    if prior_evidence_consistent is False:
        contradictions.append("prior normalization marked evidence inconsistent")
    evidence_consistent = not contradictions

    if normalized_mode == "esc":
        if dropped and semantic_status == "VERIFIED":
            semantic_status = "VACUOUS_VERIFIED"
        proof_established = (
            tool_completed
            and semantic_status in _PROOF_STATUSES
            and decided_obligations_complete is not False
            and not dropped
            and normalized_tool in _PROOF_CLAIM
            and evidence_consistent
            and prior_request_satisfied is not False
        )
        decided_claim = _PROOF_CLAIM[normalized_tool] if proof_established else "NO_PROOF"
        request_satisfied = proof_established
    else:
        request_satisfied = (
            tool_completed
            and semantic_status in _NON_PROOF_SUCCESS.get(normalized_mode, set())
            and evidence_consistent
            and prior_request_satisfied is not False
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

    return VerificationDecision(
        tool=normalized_tool,
        mode=normalized_mode,
        tool_exit_code=int(exit_code),
        tool_completed=tool_completed,
        verification=semantic_status,
        claim=decided_claim,
        request_satisfied=request_satisfied,
        dropped_obligations=dropped,
        obligations_complete=decided_obligations_complete,
        evidence_consistent=evidence_consistent,
        contradictions=tuple(contradictions),
    ).as_dict()


def decide_result(result: Mapping[str, Any], *, tool: str, mode: str) -> dict[str, Any]:
    """Normalize backend evidence without discarding prior negative evidence.

    Reapplying this function for the same request is assurance-idempotent:
    once a payload is unsatisfied, incomplete, dropped, or inconsistent, a
    subsequent normalization cannot strengthen it.
    """
    output = str(result.get("output") or result.get("message") or "")
    exit_code = int(result.get("tool_exit_code", result.get("exit_code", 1)))
    prior_consistent = _optional_bool(result, "evidence_consistent")
    if _conflicting_fields(result, "status", "verification") or \
            _conflicting_fields(result, "exit_code", "tool_exit_code"):
        prior_consistent = False
    decision = decide_verification(
        tool=tool,
        mode=mode,
        exit_code=exit_code,
        output=output,
        status=_optional_str(result.get("verification", result.get("status"))),
        claim=str(result.get("claim")) if result.get("claim") is not None else None,
        proved_obligations=_optional_int(result.get("proved_goals")),
        total_obligations=_optional_int(result.get("total_goals")),
        dropped_obligations=_optional_bool(result, "dropped_obligations"),
        obligations_complete=_optional_bool(result, "obligations_complete"),
        prior_request_satisfied=_optional_bool(result, "request_satisfied"),
        prior_tool_completed=_optional_bool(result, "tool_completed"),
        prior_evidence_consistent=prior_consistent,
    )
    return {**result, **decision}


def _optional_int(value: Any) -> int | None:
    return int(value) if value is not None else None


def _optional_str(value: Any) -> str | None:
    return str(value) if value is not None else None


def _optional_bool(result: Mapping[str, Any], key: str) -> bool | None:
    value = result.get(key)
    return value if isinstance(value, bool) else None


def _conflicting_fields(result: Mapping[str, Any], left: str, right: str) -> bool:
    return left in result and right in result and result[left] != result[right]
