# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only promotion of the M91.5c guest IMSIC policy."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from .riscv_guest_interrupt import (CLAIM, validate_guest_interrupt_claim,
                                    validate_guest_interrupt_policy,
                                    write_guest_interrupt_evidence)
from .riscv_platform_promotion import _write_atomic

def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def promote_riscv_guest_interrupt_policy(project_root: str | Path, *,
                                         accept_candidate_sha256: str) -> dict:
    root = Path(project_root).resolve(); kernel = root / "examples/formalkernel/kernel"
    candidate = kernel / "riscv_vs_imsic_policy.json"
    reviewed = kernel / "riscv_vs_imsic_policy.reviewed.json"
    digest = _sha(candidate.read_bytes())
    if digest != accept_candidate_sha256:
        raise ValueError("CRITICAL: RISC-V VS IMSIC policy candidate hash mismatch")
    policy = json.loads(candidate.read_text(encoding="utf-8"))
    failures = validate_guest_interrupt_policy(policy)
    if failures:
        raise ValueError("RISC-V VS IMSIC candidate invalid: " + ",".join(failures))
    qualification = json.loads((kernel / "riscv_vs_imsic.qualification.json").read_text())
    if (qualification.get("candidate_policy_sha256") != digest
            or qualification.get("base_status") != "VERIFIED"
            or qualification.get("semantic_mutations_rejected") != 6):
        raise ValueError("RISC-V VS IMSIC qualification stale or incomplete")
    policy.update(status="REVIEWED_RISCV_VS_IMSIC_POLICY",
                  accepted_candidate_sha256=digest,
                  review_scope="guest_file_ownership_vgein_identity_and_switch_lifecycle")
    _write_atomic(reviewed, policy)
    artifact_path = kernel / "riscv_vs_imsic.json"
    artifact = json.loads(artifact_path.read_text())
    artifact["reviewed_policy"] = {"path": reviewed.relative_to(root).as_posix(),
                                   "sha256": _sha(reviewed.read_bytes())}
    _write_atomic(artifact_path, artifact)
    evidence = validate_guest_interrupt_claim(artifact, root)
    if evidence.get("claim") != CLAIM:
        raise ValueError("RISC-V VS IMSIC post-promotion replay failed: " + str(evidence.get("code")))
    write_guest_interrupt_evidence(kernel / artifact["validation"], evidence)
    return {"status": "RISCV_VS_IMSIC_POLICY_PROMOTED", "claim": "NO_PROOF",
            "accepted_candidate_sha256": digest,
            "reviewed_policy": reviewed.relative_to(root).as_posix(),
            "post_promotion_claim": CLAIM}
