# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only exact-hash promotion of the M91.3 Sv39 mapping plan."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .riscv_platform_promotion import _write_atomic
from .riscv_sv39 import verify_sv39_isolation, write_sv39_evidence


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def promote_riscv_sv39_plan(project_root: str | Path, *,
                            accept_candidate_sha256: str) -> dict:
    root = Path(project_root).resolve()
    kernel = root / "examples/formalkernel/kernel"
    candidate = kernel / "riscv_sv39_plan.json"
    reviewed = kernel / "riscv_sv39_plan.reviewed.json"
    digest = _sha(candidate.read_bytes())
    if digest != accept_candidate_sha256:
        raise ValueError("CRITICAL: RISC-V Sv39 mapping-plan candidate hash mismatch")
    value = json.loads(candidate.read_text(encoding="utf-8"))
    if value.get("status") != "HUMAN_REVIEW_PENDING":
        raise ValueError("RISC-V Sv39 candidate is not pending human review")
    value.update(status="REVIEWED_RISCV_SV39_MAPPING_PLAN",
                 accepted_candidate_sha256=digest,
                 review_scope="descriptor_mapping_intent_not_hardware_page_walk")
    _write_atomic(reviewed, value)
    artifact_path = kernel / "riscv_sv39.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["mapping_plan"] = {
        "path": reviewed.relative_to(root).as_posix(),
        "sha256": _sha(reviewed.read_bytes()),
    }
    _write_atomic(artifact_path, artifact)
    evidence = verify_sv39_isolation(artifact, root)
    if evidence.get("claim") != "RISCV_SPATIAL_ISOLATION_PROVED":
        raise ValueError(f"RISC-V Sv39 post-promotion replay failed: {evidence.get('code')}")
    write_sv39_evidence(kernel / artifact["validation"], evidence)
    return {"status": "RISCV_SV39_MAPPING_PLAN_PROMOTED", "claim": "NO_PROOF",
            "accepted_candidate_sha256": digest,
            "reviewed_plan": reviewed.relative_to(root).as_posix(),
            "reviewed_plan_sha256": _sha(reviewed.read_bytes()),
            "post_promotion_claim": evidence["claim"]}
