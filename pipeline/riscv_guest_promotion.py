# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only exact-hash promotion of the M91.5a HS/VS policy."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from .riscv_guest_privilege import (validate_guest_policy, validate_guest_transition,
                                    write_guest_evidence)
from .riscv_platform_promotion import _write_atomic

def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def promote_riscv_guest_policy(project_root: str | Path, *,
                               accept_candidate_sha256: str) -> dict:
    root = Path(project_root).resolve()
    kernel = root / "examples/formalkernel/kernel"
    candidate = kernel / "riscv_hs_vs_policy.json"
    reviewed = kernel / "riscv_hs_vs_policy.reviewed.json"
    digest = _sha(candidate.read_bytes())
    if digest != accept_candidate_sha256:
        raise ValueError("CRITICAL: RISC-V HS/VS policy candidate hash mismatch")
    policy = json.loads(candidate.read_text(encoding="utf-8"))
    failures = validate_guest_policy(policy)
    if failures:
        raise ValueError("RISC-V HS/VS candidate invalid: " + ",".join(failures))
    qualification = json.loads(
        (kernel / "riscv_hs_vs.qualification.json").read_text(encoding="utf-8"))
    if (qualification.get("candidate_policy_sha256") != digest
            or qualification.get("base_status") != "VERIFIED"
            or qualification.get("semantic_mutations_rejected") != 4):
        raise ValueError("RISC-V HS/VS qualification stale or incomplete")
    policy.update(status="REVIEWED_RISCV_HS_VS_POLICY",
                  accepted_candidate_sha256=digest,
                  review_scope="hs_vs_guest_context_and_vmid_policy")
    _write_atomic(reviewed, policy)
    artifact_path = kernel / "riscv_hs_vs.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["reviewed_policy"] = {
        "path": reviewed.relative_to(root).as_posix(),
        "sha256": _sha(reviewed.read_bytes())}
    _write_atomic(artifact_path, artifact)
    evidence = validate_guest_transition(artifact, root)
    if evidence.get("claim") != "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED":
        raise ValueError(f"RISC-V HS/VS post-promotion replay failed: {evidence.get('code')}")
    write_guest_evidence(kernel / artifact["validation"], evidence)
    return {"status": "RISCV_HS_VS_POLICY_PROMOTED", "claim": "NO_PROOF",
            "accepted_candidate_sha256": digest,
            "reviewed_policy": reviewed.relative_to(root).as_posix(),
            "post_promotion_claim": evidence["claim"]}
