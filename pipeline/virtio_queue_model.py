# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic structural validation for the M86.3 queue-model candidate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def validate_queue_model(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    model = json.loads(raw)
    capacity = model["capacity"]
    submit = model["operations"]["submit"]
    complete = model["operations"]["complete"]
    errors = []
    states = set(range(capacity + 1))
    transitions = submit + complete
    if model["state"] != {"outstanding_min": 0, "outstanding_max": capacity}:
        errors.append("STATE_BOUND_MISMATCH")
    if any(item["pre"] not in states or item["post"] not in states for item in transitions):
        errors.append("TRANSITION_OUT_OF_BOUNDS")
    submit_pairs = {(item["pre"], item["result"], item["post"]) for item in submit}
    complete_pairs = {(item["pre"], item["result"], item["post"]) for item in complete}
    expected_submit = {
        (0, "Accepted", 1), (0, "Rejected", 0),
        (1, "Accepted", 2), (1, "Rejected", 1),
        (2, "Full", 2),
    }
    expected_complete = {
        (0, "Empty", 0), (1, "Completed", 0), (2, "Completed", 1),
    }
    if submit_pairs != expected_submit:
        errors.append("SUBMIT_RELATION_MISMATCH")
    if complete_pairs != expected_complete:
        errors.append("COMPLETE_RELATION_MISMATCH")
    return {
        "status": "VALIDATED_CANDIDATE" if not errors else "MODEL_VALIDATION_FAILED",
        "claim": "NO_PROOF",
        "candidate_sha256": hashlib.sha256(raw).hexdigest(),
        "capacity": capacity,
        "state_count": len(states),
        "transition_count": len(transitions),
        "errors": errors,
        "human_review_accepted": model["human_review"]["accepted"],
    }
