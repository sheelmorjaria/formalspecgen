# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only exact-hash promotion of the M91.4 AIA routing policy."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .riscv_aia import validate_aia_policy, validate_aia_routing, write_aia_evidence
from .riscv_platform_promotion import _write_atomic


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def promote_riscv_aia_policy(project_root: str | Path, *,
                             accept_candidate_sha256: str) -> dict:
    root = Path(project_root).resolve()
    kernel = root / "examples/formalkernel/kernel"
    candidate = kernel / "riscv_aia_policy.json"
    reviewed = kernel / "riscv_aia_policy.reviewed.json"
    qualification = json.loads(
        (kernel / "riscv_aia.qualification.json").read_text(encoding="utf-8"))
    digest = _sha(candidate.read_bytes())
    if digest != accept_candidate_sha256:
        raise ValueError("CRITICAL: RISC-V AIA policy candidate hash mismatch")
    policy = json.loads(candidate.read_text(encoding="utf-8"))
    failures = validate_aia_policy(policy, reviewed=False)
    if failures:
        raise ValueError("RISC-V AIA candidate is invalid: " + ",".join(failures))
    if (qualification.get("candidate_policy_sha256") != digest
            or qualification.get("base_status") != "VERIFIED"
            or qualification.get("semantic_mutations_rejected") != 5):
        raise ValueError("RISC-V AIA qualification evidence is stale or incomplete")
    policy.update(status="REVIEWED_RISCV_AIA_ROUTING_POLICY",
                  accepted_candidate_sha256=digest,
                  review_scope="source_hart_smode_file_interrupt_identity_policy")
    _write_atomic(reviewed, policy)
    artifact_path = kernel / "riscv_aia.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["reviewed_policy"] = {
        "path": reviewed.relative_to(root).as_posix(),
        "sha256": _sha(reviewed.read_bytes()),
    }
    _write_atomic(artifact_path, artifact)
    evidence = validate_aia_routing(artifact, root)
    if evidence.get("claim") != "RISCV_INTERRUPT_ROUTING_MODEL_PROVED":
        raise ValueError(f"RISC-V AIA post-promotion replay failed: {evidence.get('code')}")
    write_aia_evidence(kernel / artifact["validation"], evidence)
    return {"status": "RISCV_AIA_ROUTING_POLICY_PROMOTED", "claim": "NO_PROOF",
            "accepted_candidate_sha256": digest,
            "reviewed_policy": reviewed.relative_to(root).as_posix(),
            "reviewed_policy_sha256": _sha(reviewed.read_bytes()),
            "post_promotion_claim": evidence["claim"]}
