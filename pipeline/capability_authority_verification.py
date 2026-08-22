# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M89.2 parameterized TLAPS authority and closed-creation judgment."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import config


_PROOF_RELATIVE = Path(
    "examples/formalkernel/kernel/capability/CapabilityAuthorityRefinement.tla")
_MUTATIONS = {
    "unauthorized_root_mint": (
        "caller \\in RootAuthorities", "caller \\in Principals"),
    "derive_rights_amplification": (
        "newRights \\subseteq parent.rights", "newRights \\subseteq Rights"),
    "derive_object_substitution": (
        "newObject = parent.object", "newObject \\in Objects"),
    "forged_creation_origin": (
        'origin |-> "derive"', 'origin |-> "root"'),
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _tool_hash(path: str) -> str:
    return _sha256(Path(path).read_bytes())


def _tlapm() -> str | None:
    configured = Path(config.TLAPM_BIN).expanduser()
    if configured.is_file() and os.access(configured, os.X_OK):
        return str(configured.resolve())
    return shutil.which("tlapm")


def _run(tlapm: str, proof: str) -> tuple[bool, str, int]:
    with tempfile.TemporaryDirectory(prefix="formalkernel-m89-tlaps-") as directory:
        root = Path(directory)
        source = root / "CapabilityAuthorityRefinement.tla"
        source.write_text(proof, encoding="utf-8")
        home = root / "home"
        home.mkdir()
        environment = os.environ.copy()
        environment["HOME"] = str(home)
        try:
            result = subprocess.run(
                [tlapm, "--cleanfp", "--nofp", source.name], cwd=root,
                capture_output=True, text=True, timeout=300, env=environment,
                check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc), -1
    output = (result.stdout or "") + (result.stderr or "")
    return (result.returncode == 0 and "All 12 obligations proved" in output,
            output, result.returncode)


def verify_capability_authority(
        reviewed_model: str | Path, project_root: str | Path) -> dict:
    """Prove the reviewed arbitrary-finite authority algebra and reject mutations."""
    root = Path(project_root).resolve()
    reviewed_path = Path(reviewed_model).resolve()
    try:
        reviewed_raw = reviewed_path.read_bytes()
        reviewed = json.loads(reviewed_raw)
        candidate_path = reviewed_path.with_name("m89_capability_authority.candidate.json")
        candidate_raw = candidate_path.read_bytes()
        proof_raw = (root / _PROOF_RELATIVE).read_bytes()
        proof = proof_raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"status": "REVIEWED_CAPABILITY_AUTHORITY_REQUIRED",
                "claim": "NO_PROOF", "message": str(exc)}
    if (reviewed.get("status") != "REVIEWED_CAPABILITY_AUTHORITY_MODEL"
            or reviewed.get("review_status") != "reviewed"
            or reviewed.get("accepted_candidate_sha256") != _sha256(candidate_raw)):
        return {"status": "REVIEWED_CAPABILITY_AUTHORITY_REQUIRED", "claim": "NO_PROOF"}
    required = (
        "THEOREM InitImpliesInv", "THEOREM InvIsInductive",
        "AuthorityAttenuated", "CreationClosed",
    )
    if any(marker not in proof for marker in required):
        return {"status": "CAPABILITY_AUTHORITY_PROOF_BINDING_FAILED",
                "claim": "NO_PROOF"}
    tlapm = _tlapm()
    if tlapm is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "judge_pending": "tlapm"}
    proved, output, exit_code = _run(tlapm, proof)
    if not proved:
        return {"status": "CAPABILITY_AUTHORITY_TLAPS_FAILED", "claim": "NO_PROOF",
                "exit_code": exit_code, "output_tail": output[-1000:]}

    mutations = []
    for mutation_id, (old, new) in _MUTATIONS.items():
        if proof.count(old) < 1:
            return {"status": "CAPABILITY_AUTHORITY_MUTATION_BINDING_FAILED",
                    "claim": "NO_PROOF", "mutation": mutation_id}
        mutated = proof.replace(old, new, 1)
        survived, mutation_output, mutation_exit = _run(tlapm, mutated)
        if survived:
            return {"status": "CAPABILITY_AUTHORITY_MUTATION_SURVIVED",
                    "claim": "NO_PROOF", "mutation": mutation_id}
        mutations.append({
            "id": mutation_id,
            "result": "rejected",
            "mutated_proof_sha256": _sha256(mutated.encode()),
            "output_sha256": _sha256(mutation_output.encode()),
            "exit_code": mutation_exit,
        })
    version = subprocess.run([tlapm, "--version"], capture_output=True,
                             text=True, timeout=10, check=False)
    return {
        "status": "CAPABILITY_TOKEN_CREATION_CLOSED_PROVED",
        "claim": "CAPABILITY_TOKEN_CREATION_CLOSED_PROVED",
        "claims_minted": [
            "CAPABILITY_AUTHORITY_ALGEBRA_PROVED",
            "CAPABILITY_TOKEN_CREATION_CLOSED_PROVED",
        ],
        "judge": "tlapm",
        "judge_version": version.stdout.strip(),
        "judge_executable_sha256": _tool_hash(tlapm),
        "scope": "arbitrary_finite_capability_authority_algebra",
        "reviewed_model_sha256": _sha256(reviewed_raw),
        "accepted_candidate_sha256": _sha256(candidate_raw),
        "proof_sha256": _sha256(proof_raw),
        "verifier_sha256": _tool_hash(str(Path(__file__).resolve())),
        "proof_output_sha256": _sha256(output.encode()),
        "tlaps_obligations_proved": 12,
        "mutations_executed": len(mutations),
        "mutations_rejected": len(mutations),
        "mutations": mutations,
        "parameterized_over": ["finite principals", "finite objects", "finite rights"],
        "claims_locked": [
            "CAPABILITY_REVOCATION_SAFETY_PROVED",
            "SERVER_AUTHORITY_SECURITY_MODEL_PROVED",
            "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED",
            "CAPABILITY_HARDWARE_ENFORCEMENT_PROVED",
            "CAPABILITY_IMPLEMENTATION_REFINEMENT_PROVED",
        ],
    }
