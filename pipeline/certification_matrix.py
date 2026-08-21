# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M70 deterministic OS evidence-to-requirement traceability gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "CERTIFICATION_TRACEABILITY_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_certification_traceability(path: str | Path, deployment: str,
                                      claims: list[dict],
                                      boundaries: list[dict]) -> dict:
    """Map applicable requirements to minted evidence without certifying it."""
    artifact_path = Path(path)
    try:
        raw = artifact_path.read_bytes()
        artifact = json.loads(raw)
        requirements = artifact["requirements"]
        physical = artifact["required_physical_closures"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("CERTIFICATION_TRACEABILITY_ARTIFACT_INVALID", str(exc))
    if artifact.get("certification_claim_forbidden") is not True:
        return _fail("CERTIFICATION_CLAIM_CEILING_MISSING")
    if not isinstance(requirements, list) or not requirements:
        return _fail("CERTIFICATION_REQUIREMENTS_MISSING")
    rows = []
    ids: set[str] = set()
    for requirement in requirements:
        try:
            req_id = requirement["id"]
            expected = requirement["claim"]
            profiles = requirement["profiles"]
        except (KeyError, TypeError) as exc:
            return _fail("CERTIFICATION_REQUIREMENT_INVALID", str(exc))
        if req_id in ids or not isinstance(profiles, list):
            return _fail("CERTIFICATION_REQUIREMENT_INVALID", req_id)
        ids.add(req_id)
        if deployment not in profiles:
            continue
        matches = [entry for entry in claims if entry.get("claim") == expected
                   and entry.get("status") != "judge_pending"]
        rows.append({"requirement": req_id, "claim": expected,
                     "status": "MAPPED" if matches else "UNMAPPED",
                     "evidence_count": len(matches),
                     "judges": sorted({entry.get("judge", "unknown")
                                        for entry in matches}),
                     "sources": sorted({entry.get("source", "")
                                         for entry in matches})})
    missing = [row["requirement"] for row in rows if row["status"] == "UNMAPPED"]
    boundary_names = {entry.get("claim") for entry in boundaries}
    physical_pending = [name for name in physical if name in boundary_names]
    fingerprint_rows = [{key: entry.get(key) for key in
                         ("claim", "scope", "profile", "source", "judge")}
                        for entry in claims]
    fingerprint = hashlib.sha256(json.dumps(
        fingerprint_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if missing:
        return {"status": "CERTIFICATION_TRACEABILITY_PENDING",
                "claim": "NO_PROOF", "code": "TRACEABILITY_UNMAPPED",
                "missing_requirements": missing, "rows": rows,
                "artifact_sha256": hashlib.sha256(raw).hexdigest(),
                "evidence_fingerprint_sha256": fingerprint}
    return {
        "status": "CERTIFICATION_TRACEABILITY_COMPLETE",
        "claim": "CERTIFICATION_TRACEABILITY_COMPLETE",
        "judge": "deterministic_gate", "deployment": deployment,
        "rows": rows, "mapped": len(rows), "total": len(rows),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "evidence_fingerprint_sha256": fingerprint,
        "physical_closures_pending": physical_pending,
        "certification_ready": False,
        "regulatory_certification_proved": False,
    }
