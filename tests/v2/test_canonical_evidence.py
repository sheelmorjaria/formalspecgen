# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json

import pytest

from pipeline.domain_v2_evidence import (
    build_evidence_envelope, canonical_bytes, canonical_sha256,
    verify_evidence_envelope,
)


def test_canonical_json_is_compact_utf8_and_recursively_sorted():
    value = {"z": {"é": 2, "a": 1}, "a": [3, {"y": 2, "x": 1}]}
    encoded = canonical_bytes(value)
    assert encoded == '{"a":[3,{"x":1,"y":2}],"z":{"a":1,"é":2}}'.encode()
    assert b" " not in encoded
    assert canonical_sha256(value) == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_numbers(invalid):
    with pytest.raises(ValueError):
        canonical_bytes({"measurement": invalid})


def test_envelope_hash_covers_inner_evidence_only():
    evidence = {"schema_version": 2, "validation_status": "VALIDATED",
                "reachable_state_count": 42}
    envelope = build_evidence_envelope(evidence)
    assert envelope["evidence"] == evidence
    assert envelope["evidence_sha256"] == canonical_sha256(evidence)
    assert envelope["evidence_sha256"] != canonical_sha256(envelope)
    assert verify_evidence_envelope(envelope)


def test_envelope_verification_rejects_evidence_or_digest_tampering():
    envelope = build_evidence_envelope({"status": "VALIDATED", "states": 2})
    envelope["evidence"]["states"] = 3
    assert not verify_evidence_envelope(envelope)
    envelope = build_evidence_envelope({"status": "VALIDATED", "states": 2})
    envelope["evidence_sha256"] = "0" * 64
    assert not verify_evidence_envelope(envelope)


def test_envelope_builder_copies_input_and_rejects_invalid_shape():
    evidence = {"nested": {"count": 1}}
    envelope = build_evidence_envelope(evidence)
    evidence["nested"]["count"] = 99
    assert envelope["evidence"]["nested"]["count"] == 1
    assert not verify_evidence_envelope({})
    assert not verify_evidence_envelope({"evidence": [], "evidence_sha256": "x"})
    assert not verify_evidence_envelope(
        {"evidence": {}, "evidence_sha256": 123})
    assert not verify_evidence_envelope(
        {"evidence": {"bad": float("nan")}, "evidence_sha256": "x"})
