# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import json
from pathlib import Path

from pipeline.capability_registry import capability, mcp_capabilities
from pipeline.deployment_sealing import (
    seal_deployment_evidence,
    validate_deployment_seal,
)
from pipeline.proof_carrying_build import _hash_json


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
BINARY = KERNEL / "m90_binary_evidence.json"
INVALIDATION = KERNEL / "m90_invalidation.validation.json"
REPRO = KERNEL / "m90_reproducibility.validation.json"
ELF_HASH = "1a8d4e1113d9fdd2a948e0f9c739303d4690eb39588a3505475564165d88d3c9"
ROOT_HASH = "36f4e6cd9ce8a26cebea3c9913935d143856b6593d29e57fa6c99cd6493ecd8e"
TIMESTAMP = "2026-08-21T12:00:00+00:00"


def _seal(tmp_path: Path):
    return seal_deployment_evidence(
        ROOT, accept_elf_sha256=ELF_HASH,
        accept_evidence_root_sha256=ROOT_HASH,
        release="m90.5-test-release", output_path=tmp_path / "release.json",
        release_timestamp=TIMESTAMP)


def test_human_exact_hash_seal_binds_positive_and_residual_evidence(tmp_path):
    sealed = _seal(tmp_path)
    assert sealed["status"] == "SEALED_DEPLOYMENT_EVIDENCE"
    assert sealed["claim"] == "NO_PROOF"
    assert sealed["approval"]["method"] == "human_explicit_hash_acceptance"
    assert sealed["applicable_claims"] == [
        "SYSTEM_COMPOSITION_PROVED", "RUST_WITNESS_REFINEMENT_PROVED"]
    assert sealed["residuals"]["applicable_pending"] == []
    assert sealed["residuals"]["repository_judge_pending_inventory"]
    assert sealed["residuals"]["assumptions"]
    assert sealed["residuals"]["forbidden_claims"]
    assert sealed["residuals"]["not_applicable_bundle_claims"]
    assert validate_deployment_seal(sealed, ROOT)["status"] == (
        "SEALED_DEPLOYMENT_EVIDENCE")


def test_wrong_explicit_hashes_and_pending_policy_refuse_before_write(tmp_path):
    wrong_elf = seal_deployment_evidence(
        ROOT, accept_elf_sha256="0" * 64,
        accept_evidence_root_sha256=ROOT_HASH, release="wrong-elf",
        output_path=tmp_path / "wrong-elf.json", release_timestamp=TIMESTAMP)
    assert wrong_elf["code"] == "M90_SEAL_ELF_HASH_NOT_ACCEPTED"
    wrong_root = seal_deployment_evidence(
        ROOT, accept_elf_sha256=ELF_HASH,
        accept_evidence_root_sha256="0" * 64, release="wrong-root",
        output_path=tmp_path / "wrong-root.json", release_timestamp=TIMESTAMP)
    assert wrong_root["code"] == "M90_SEAL_EVIDENCE_ROOT_NOT_ACCEPTED"
    pending = seal_deployment_evidence(
        ROOT, accept_elf_sha256=ELF_HASH,
        accept_evidence_root_sha256=ROOT_HASH, release="wrong-pending",
        allowed_pending=["physical_silicon_correspondence"],
        output_path=tmp_path / "pending.json", release_timestamp=TIMESTAMP)
    assert pending["code"] == "M90_SEAL_PENDING_POLICY_MISMATCH"
    assert not list(tmp_path.glob("*.json"))


def test_stale_invalidation_and_modified_binary_evidence_refuse(tmp_path):
    stale_invalidation = json.loads(INVALIDATION.read_text())
    stale_invalidation["dependency_graph"]["graph_digest"] = "0" * 64
    stale_path = tmp_path / "stale-invalidation.json"
    stale_path.write_text(json.dumps(stale_invalidation))
    result = seal_deployment_evidence(
        ROOT, accept_elf_sha256=ELF_HASH,
        accept_evidence_root_sha256=ROOT_HASH, release="stale-invalidation",
        invalidation_path=stale_path, output_path=tmp_path / "seal-a.json",
        release_timestamp=TIMESTAMP)
    assert result["code"] == "M90_SEAL_INVALIDATION_EVIDENCE_STALE"

    changed_binary = json.loads(BINARY.read_text())
    changed_binary["applicable_claims"].pop()
    changed_path = tmp_path / "changed-binary.json"
    changed_path.write_text(json.dumps(changed_binary))
    result = seal_deployment_evidence(
        ROOT, accept_elf_sha256=ELF_HASH,
        accept_evidence_root_sha256=ROOT_HASH, release="missing-claim",
        binary_evidence_path=changed_path, output_path=tmp_path / "seal-b.json",
        release_timestamp=TIMESTAMP)
    assert result["code"] == "M90_SEAL_BINARY_EVIDENCE_INVALID"


def test_residual_or_release_metadata_changes_break_the_content_seal(tmp_path):
    sealed = _seal(tmp_path)
    assumption = copy.deepcopy(sealed)
    assumption["residuals"]["assumptions"].pop()
    assert validate_deployment_seal(assumption, ROOT)["code"] == "M90_SEAL_CONTENT_CHANGED"
    forbidden = copy.deepcopy(sealed)
    forbidden["residuals"]["forbidden_claims"].pop()
    assert validate_deployment_seal(forbidden, ROOT)["code"] == "M90_SEAL_CONTENT_CHANGED"
    release = copy.deepcopy(sealed)
    release["release_identity"] = "changed-release"
    assert validate_deployment_seal(release, ROOT)["code"] == "M90_SEAL_CONTENT_CHANGED"

    # Even recomputing the unkeyed content digest cannot hide an incomplete envelope.
    recomputed = copy.deepcopy(sealed)
    recomputed["residuals"]["assumptions"].pop()
    unsigned = {key: value for key, value in recomputed.items()
                if key not in {"seal_sha256", "sealed_artifact"}}
    recomputed["seal_sha256"] = _hash_json(unsigned)
    assert validate_deployment_seal(recomputed, ROOT)["code"] == (
        "M90_SEAL_ENVELOPE_INCOMPLETE_OR_STALE")


def test_existing_release_is_never_overwritten(tmp_path):
    output = tmp_path / "once.json"
    first = seal_deployment_evidence(
        ROOT, accept_elf_sha256=ELF_HASH,
        accept_evidence_root_sha256=ROOT_HASH, release="one-release",
        output_path=output, release_timestamp=TIMESTAMP)
    assert first["status"] == "SEALED_DEPLOYMENT_EVIDENCE"
    original_digest = hashlib.sha256(output.read_bytes()).hexdigest()
    second = seal_deployment_evidence(
        ROOT, accept_elf_sha256=ELF_HASH,
        accept_evidence_root_sha256=ROOT_HASH, release="one-release",
        output_path=output, release_timestamp=TIMESTAMP)
    assert second["code"] == "M90_RELEASE_ALREADY_SEALED"
    assert hashlib.sha256(output.read_bytes()).hexdigest() == original_digest


def test_sealing_is_registered_human_only_and_absent_from_mcp():
    spec = capability("seal_deployment_evidence")
    assert spec.trust_action is True
    assert spec.cli_command == "seal-deployment-evidence"
    assert spec.mcp_tool is None
    assert all(item.name != "seal_deployment_evidence" for item in mcp_capabilities())
    milestone = capability("m90_5_human_release_sealing").milestone
    assert milestone is not None
    assert milestone.current_step == 5
    assert milestone.current_maturity == "proof-carrying-deployment-frozen"
    assert milestone.completed_claims == ("SEALED_DEPLOYMENT_EVIDENCE",)
