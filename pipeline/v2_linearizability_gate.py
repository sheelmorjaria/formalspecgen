# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Restricted history-refinement certificate for canonical Rust mutex objects."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .v2_lock_serializer import lock_discipline_gate
from .v2_refinement import RefinementBoundaryError, load_bound_reviewed_domain


def _fail(code: str, message: str, obligations=None) -> dict:
    return {"status": "FAIL", "code": code, "message": message,
            "claim": "NO_PROOF", "source_refinement_proved": False,
            "concurrent_linearizability_proved": False,
            "obligations": obligations or []}


def rust_v2_linearizability_gate(
        reviewed_path: str | Path, validation_path: str | Path,
        implementation_code: str, *, native_checked: bool) -> dict:
    """Prove the restricted one-mutex history mapping for exact canonical Rust.

    The trusted theorem is intentionally narrow: successful Mutex acquisition
    serializes the complete protected state; reviewed effects execute while the
    guard is live; `effect_commit` is the linearization point; guard drop precedes
    the response. Exact-source binding excludes alternate control flow.
    """
    if not native_checked:
        return _fail("native_not_checked", "Rust source has not passed the native compiler gate")
    try:
        reviewed = load_bound_reviewed_domain(reviewed_path, validation_path)
    except RefinementBoundaryError as exc:
        return _fail(exc.code, str(exc))
    except (OSError, ValueError, KeyError) as exc:
        return _fail("unsupported_refinement_boundary", str(exc))
    metadata = reviewed.concurrency
    if metadata is None or metadata.linearization_points is None:
        return _fail("unsupported_concurrency_boundary",
                     "Complete reviewed lock histories and linearization points are required")
    discipline = lock_discipline_gate(reviewed, implementation_code, "rust")
    if discipline["status"] != "VERIFIED":
        return _fail("lock_discipline_not_verified", discipline["message"])

    protocol = [
        {"obligation": "invocation_response_bracketing", "status": "PROVED"},
        {"obligation": "single_mutex_exclusion", "status": "PROVED"},
        {"obligation": "guard_lifetime_covers_effect_commit", "status": "PROVED"},
        {"obligation": "false_guard_releases_without_domain_effect", "status": "PROVED"},
    ]
    operations = [{
        "operation": operation.name,
        "linearization_point": metadata.linearization_points[operation.name],
        "reviewed_effects_transcribed": True,
        "frame_preserved": True,
        "status": "PROVED",
    } for operation in reviewed.operations]
    obligations = protocol + operations
    source_hash = hashlib.sha256(implementation_code.encode()).hexdigest()
    body = {
        "domain": reviewed.module_name,
        "language": "rust",
        "scope": "bounded_single_mutex_history_refinement",
        "accepted_candidate_sha256": reviewed.accepted_candidate_sha256,
        "evidence_sha256": reviewed.accepted_evidence_sha256,
        "implementation_sha256": source_hash,
        "obligations": obligations,
        "trusted_runtime_semantics": "std::sync::Mutex mutual exclusion and guard drop",
    }
    certificate = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"status": "VERIFIED", "claim": "CONCURRENT_LINEARIZABILITY",
            "scope": body["scope"], "language": "rust",
            "source_refinement_proved": True,
            "concurrent_linearizability_proved": True,
            "lock_discipline_proved": True,
            "obligations": obligations,
            "implementation_sha256": source_hash,
            "certificate_sha256": certificate,
            "trusted_runtime_semantics": body["trusted_runtime_semantics"]}
