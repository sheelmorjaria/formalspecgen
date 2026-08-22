# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only promotion of the M91.5b G-stage plan."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from .riscv_gstage import validate_gstage_claim, validate_gstage_plan, write_gstage_evidence
from .riscv_platform_promotion import _write_atomic
def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
def promote_riscv_gstage_plan(project_root: str | Path, *,
                              accept_candidate_sha256: str) -> dict:
    root = Path(project_root).resolve(); kernel = root / "examples/formalkernel/kernel"
    candidate = kernel / "riscv_gstage_plan.json"
    reviewed = kernel / "riscv_gstage_plan.reviewed.json"
    digest = _sha(candidate.read_bytes())
    if digest != accept_candidate_sha256:
        raise ValueError("CRITICAL: RISC-V G-stage plan candidate hash mismatch")
    plan = json.loads(candidate.read_text(encoding="utf-8"))
    failures = validate_gstage_plan(plan)
    if failures:
        raise ValueError("RISC-V G-stage candidate invalid: " + ",".join(failures))
    qualification = json.loads(
        (kernel / "riscv_gstage.qualification.json").read_text(encoding="utf-8"))
    if (qualification.get("candidate_plan_sha256") != digest
            or qualification.get("base_status") != "VERIFIED"
            or qualification.get("semantic_mutations_rejected") != 3):
        raise ValueError("RISC-V G-stage qualification stale or incomplete")
    plan.update(status="REVIEWED_RISCV_G_STAGE_PLAN",
                accepted_candidate_sha256=digest,
                review_scope="guest_spa_vmid_hgatp_and_hfence_policy")
    _write_atomic(reviewed, plan)
    artifact_path = kernel / "riscv_gstage.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["reviewed_plan"] = {
        "path": reviewed.relative_to(root).as_posix(), "sha256": _sha(reviewed.read_bytes())}
    _write_atomic(artifact_path, artifact)
    evidence = validate_gstage_claim(artifact, root)
    if evidence.get("claim") != "RISCV_G_STAGE_ISOLATION_PROVED":
        raise ValueError(f"RISC-V G-stage post-promotion replay failed: {evidence.get('code')}")
    write_gstage_evidence(kernel / artifact["validation"], evidence)
    return {"status": "RISCV_G_STAGE_PLAN_PROMOTED", "claim": "NO_PROOF",
            "accepted_candidate_sha256": digest,
            "reviewed_plan": reviewed.relative_to(root).as_posix(),
            "post_promotion_claim": evidence["claim"]}
