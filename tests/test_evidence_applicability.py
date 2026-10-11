# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Applicability is an exact-context decision, separate from approval."""
import pytest

from pipeline.evidence_applicability import evaluate_evidence_applicability


def test_exact_context_does_not_grant_human_approval_or_authenticate_evidence():
    context = {"schema": "fixture-v1", "source": "a", "bounds": {"states": 10}}
    decision = evaluate_evidence_applicability(context, context, evidence_sha256="a" * 64)
    assert decision.applicable and decision.reasons == ()
    result = decision.as_dict()
    assert result["decision"] == "APPLICABLE"
    assert result["human_approval_required"] and not result["authenticity_established"]
    assert result["recorded_context_sha256"] == result["expected_context_sha256"]


@pytest.mark.parametrize("recorded,expected,reasons", [
    ({}, {}, ("EXPECTED_CONTEXT_EMPTY",)),
    (None, {"schema": "v1"}, ("CONTEXT_NOT_RECORDED",)),
    ({}, {"schema": "v1"}, ("MISSING:schema",)),
    ({"schema": "v2"}, {"schema": "v1"}, ("MISMATCH:schema",)),
    ({"schema": "v1", "extra": 1}, {"schema": "v1"}, ("UNEXPECTED:extra",)),
    ({"states": True}, {"states": 1}, ("MISMATCH:states",)),
    ({"states": 20}, {"states": 10}, ("MISMATCH:states",)),
])
def test_missing_different_and_extra_context_require_revalidation(recorded, expected, reasons):
    decision = evaluate_evidence_applicability(recorded, expected, evidence_sha256="a" * 64)
    assert not decision.applicable and decision.reasons == reasons
    assert decision.as_dict()["decision"] == "REVALIDATE"


@pytest.mark.parametrize("recorded,expected,digest", [
    ([], {"schema": "v1"}, "a" * 64), ({}, [], "a" * 64),
    ({}, {}, "short"), ({}, {}, None),
])
def test_malformed_context_or_digest_cannot_yield_applicable(recorded, expected, digest):
    with pytest.raises(ValueError):
        evaluate_evidence_applicability(recorded, expected, evidence_sha256=digest)
