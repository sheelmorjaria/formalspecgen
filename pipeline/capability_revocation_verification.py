# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M89.3 TLAPS judgment for transitive revocation and stale generations."""
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
    "examples/formalkernel/kernel/capability/CapabilityRevocationRefinement.tla")
_MUTATIONS = {
    "revoke_parent_leaves_descendant_valid": (
        "t.ancestors \\cap revoked' = {}", "t.ancestors \\cap revoked = {}"),
    "unrelated_mint_resets_revocation": (
        "revoked' = revoked", "revoked' = {}"),
    "generation_reuse_allowed": (
        "[id |-> newId, generation |-> generation] \\notin issued",
        "[id |-> newId, generation |-> generation] \\in Key"),
    "stale_generation_passes_check": (
        "Check(token) == /\\ Valid(token)", "Check(token) == /\\ token \\in live"),
    "stale_token_derives_child": (
        "Derive(parent, newId, generation, newOwner, newRights) ==\n    /\\ Valid(parent)",
        "Derive(parent, newId, generation, newOwner, newRights) ==\n    /\\ parent \\in live"),
    "stale_token_delegates_child": (
        "Delegate(parent, newId, generation, newOwner, newRights) ==\n    /\\ Valid(parent)",
        "Delegate(parent, newId, generation, newOwner, newRights) ==\n    /\\ parent \\in live"),
    "revoke_unrelated_branches": (
        "revoked' = revoked \\cup {token.key}", "revoked' = issued"),
    "stale_token_can_revoke": (
        "Revoke(token) ==\n    /\\ Valid(token)",
        "Revoke(token) ==\n    /\\ token \\in live"),
    "failed_stale_operation_mutates": (
        "/\\ UNCHANGED vars\n\nCheck(token)",
        "/\\ live' = live\n    /\\ issued' = issued\n"
        "    /\\ revoked' = revoked \\cup {token.key}\n\nCheck(token)"),
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _tlapm() -> str | None:
    configured = Path(config.TLAPM_BIN).expanduser()
    if configured.is_file() and os.access(configured, os.X_OK):
        return str(configured.resolve())
    return shutil.which("tlapm")


def _run(tlapm: str, proof: str) -> tuple[bool, str, int]:
    with tempfile.TemporaryDirectory(prefix="formalkernel-m89-revoke-") as directory:
        root = Path(directory)
        source = root / "CapabilityRevocationRefinement.tla"
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
    return (result.returncode == 0 and "All 10 obligations proved" in output,
            output, result.returncode)


def verify_capability_revocation(
        reviewed_model: str | Path, project_root: str | Path) -> dict:
    """Judge transitive revocation, persistence, and stale-generation rejection."""
    root = Path(project_root).resolve()
    reviewed_path = Path(reviewed_model).resolve()
    try:
        reviewed_raw = reviewed_path.read_bytes()
        reviewed = json.loads(reviewed_raw)
        candidate_raw = reviewed_path.with_name(
            "m89_capability_authority.candidate.json").read_bytes()
        authority_evidence_raw = reviewed_path.with_name(
            "m89_capability_authority.validation.json").read_bytes()
        authority_evidence = json.loads(authority_evidence_raw)
        proof_raw = (root / _PROOF_RELATIVE).read_bytes()
        proof = proof_raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"status": "M89_AUTHORITY_PREREQUISITE_REQUIRED",
                "claim": "NO_PROOF", "message": str(exc)}
    if (reviewed.get("status") != "REVIEWED_CAPABILITY_AUTHORITY_MODEL"
            or reviewed.get("accepted_candidate_sha256") != _sha256(candidate_raw)
            or "CAPABILITY_TOKEN_CREATION_CLOSED_PROVED"
            not in authority_evidence.get("claims_minted", [])):
        return {"status": "M89_AUTHORITY_PREREQUISITE_REQUIRED", "claim": "NO_PROOF"}
    required = (
        "THEOREM RevokeBlocksDescendants",
        "THEOREM RevokePreservesUnrelatedAuthority",
        "THEOREM RevocationPersists",
        "THEOREM GenerationReuseRejectsOld",
        "THEOREM StaleTokenCannotCreate",
        "THEOREM StaleTokenCannotCheck",
        "THEOREM StaleTokenCannotRevoke",
        "THEOREM FailedStaleOperationStutters",
    )
    if any(marker not in proof for marker in required):
        return {"status": "CAPABILITY_REVOCATION_PROOF_BINDING_FAILED",
                "claim": "NO_PROOF"}
    tlapm = _tlapm()
    if tlapm is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "judge_pending": "tlapm"}
    proved, output, exit_code = _run(tlapm, proof)
    if not proved:
        return {"status": "CAPABILITY_REVOCATION_TLAPS_FAILED", "claim": "NO_PROOF",
                "exit_code": exit_code, "output_tail": output[-1000:]}

    mutations = []
    for mutation_id, (old, new) in _MUTATIONS.items():
        if proof.count(old) < 1:
            return {"status": "CAPABILITY_REVOCATION_MUTATION_BINDING_FAILED",
                    "claim": "NO_PROOF", "mutation": mutation_id}
        mutated = proof.replace(old, new, 1)
        survived, mutation_output, mutation_exit = _run(tlapm, mutated)
        if survived:
            return {"status": "CAPABILITY_REVOCATION_MUTATION_SURVIVED",
                    "claim": "NO_PROOF", "mutation": mutation_id}
        mutations.append({
            "id": mutation_id, "result": "rejected",
            "mutated_proof_sha256": _sha256(mutated.encode()),
            "output_sha256": _sha256(mutation_output.encode()),
            "exit_code": mutation_exit,
        })
    version = subprocess.run([tlapm, "--version"], capture_output=True,
                             text=True, timeout=10, check=False)
    return {
        "status": "CAPABILITY_REVOCATION_SAFETY_PROVED",
        "claim": "CAPABILITY_REVOCATION_SAFETY_PROVED",
        "judge": "tlapm",
        "judge_version": version.stdout.strip(),
        "judge_executable_sha256": _sha256(Path(tlapm).read_bytes()),
        "scope": "parameterized_transitive_revocation_and_generation_safety",
        "reviewed_model_sha256": _sha256(reviewed_raw),
        "authority_evidence_sha256": _sha256(authority_evidence_raw),
        "proof_sha256": _sha256(proof_raw),
        "verifier_sha256": _sha256(Path(__file__).read_bytes()),
        "proof_output_sha256": _sha256(output.encode()),
        "tlaps_obligations_proved": 10,
        "mutations_executed": len(mutations),
        "mutations_rejected": len(mutations),
        "mutations": mutations,
        "generation_domain": "unbounded_natural",
        "fixed_width_generation_wraparound_proved": False,
        "claims_locked": [
            "SERVER_AUTHORITY_SECURITY_MODEL_PROVED",
            "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED",
            "CAPABILITY_HARDWARE_ENFORCEMENT_PROVED",
            "CAPABILITY_IMPLEMENTATION_REFINEMENT_PROVED",
        ],
    }
