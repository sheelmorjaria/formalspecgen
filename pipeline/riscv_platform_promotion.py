# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human-only exact-hash promotion of the M91.1 RISC-V platform profile."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .riscv_feasibility import _sha, inspect_riscv_feasibility


def _write_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def promote_riscv_platform(project_root: str | Path, *,
                           accept_candidate_sha256: str) -> dict:
    """Accept the profile intent without minting any RISC-V theorem."""
    root = Path(project_root).resolve()
    candidate = root / "examples/formalkernel/profiles/riscv64-qemu.candidate.json"
    reviewed = root / "examples/formalkernel/profiles/riscv64-qemu.reviewed.json"
    digest = _sha(candidate.read_bytes())
    if digest != accept_candidate_sha256:
        raise ValueError("CRITICAL: RISC-V platform candidate hash mismatch")
    feasibility = inspect_riscv_feasibility(root, candidate)
    if feasibility.get("status") != "RISCV_PLATFORM_FEASIBILITY_RECORDED" or \
            feasibility.get("claim") != "NO_PROOF":
        raise ValueError("RISC-V platform candidate fails feasibility validation")
    value = json.loads(candidate.read_text())
    value.update(status="REVIEWED_RISCV_PLATFORM_PROFILE",
                 accepted_candidate_sha256=digest,
                 review_scope="configuration_intent_not_hardware_conformance",
                 claims_minted=[])
    _write_atomic(reviewed, value)
    return {"status": "RISCV_PLATFORM_PROFILE_PROMOTED", "claim": "NO_PROOF",
            "accepted_candidate_sha256": digest,
            "reviewed_profile": reviewed.relative_to(root).as_posix(),
            "reviewed_profile_sha256": _sha(reviewed.read_bytes())}
