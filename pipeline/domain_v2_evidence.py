# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Pure canonicalization and envelope-integrity primitives for future V2 evidence.

These functions establish deterministic integrity only. They do not sign evidence, authenticate a
reviewer, publish files, validate a domain, or alter active V1 assurance behavior.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """Return the one canonical JSON encoding used by V2 SHA-256 evidence links."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def build_evidence_envelope(evidence: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy evidence and hash only that inner object, avoiding self-reference."""
    inner = copy.deepcopy(evidence)
    return {"evidence": inner, "evidence_sha256": canonical_sha256(inner)}


def verify_evidence_envelope(envelope: Any) -> bool:
    """Check structure and digest without promoting integrity into an authenticity claim."""
    if not isinstance(envelope, dict) or set(envelope) != {
            "evidence", "evidence_sha256"}:
        return False
    evidence, claimed = envelope["evidence"], envelope["evidence_sha256"]
    if not isinstance(evidence, dict) or not isinstance(claimed, str):
        return False
    try:
        actual = canonical_sha256(evidence)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(actual, claimed)
