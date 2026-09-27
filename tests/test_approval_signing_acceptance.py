# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Real GPG/protected-signer acceptance; mandatory only in provisioned CI."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from pipeline.approval_service import ApprovalService, record_human_decision
from pipeline.trust import list_trusted_keys


def test_real_authenticated_approval_and_protected_signer(tmp_path):
    if os.environ.get("FORMALSPECGEN_REQUIRE_APPROVAL_ACCEPTANCE") != "1":
        pytest.skip("real approval acceptance requires provisioned GPG identities")
    root = Path(os.environ["FORMALSPECGEN_APPROVAL_ROOT"])
    public_home = Path(os.environ["FORMALSPECGEN_APPROVAL_GNUPGHOME"])
    registry = Path(os.environ["FORMALSPECGEN_APPROVAL_TRUST_REGISTRY"])
    signer = Path(os.environ["FORMALSPECGEN_APPROVAL_SIGNER"])
    reviewer_home = Path(
        os.environ["FORMALSPECGEN_ACCEPTANCE_REVIEWER_GNUPGHOME"])
    reviewer = os.environ["FORMALSPECGEN_ACCEPTANCE_REVIEWER_KEY"]
    signing_identity = os.environ["FORMALSPECGEN_SIGNING_IDENTITY"]
    artifact = tmp_path / "refactor-result.json"
    evidence = tmp_path / "terminal-manifest.json"
    artifact.write_text('{"status":"VERIFIED"}\n', encoding="utf-8")
    evidence.write_text(json.dumps({
        "claim": "REFACTOR_CONTRACT_PRESERVED",
        "claim_limits": {"behavior_equivalence_proved": False},
    }) + "\n", encoding="utf-8")
    service = ApprovalService(
        root, verifier_home=public_home,
        authorized_reviewers={
            item["key_id"] for item in list_trusted_keys(registry)},
        signer=signer, signing_identity=signing_identity,
        reviewer_identity=reviewer)
    request = service.create_request(
        artifact=artifact, evidence_manifest=evidence,
        admission_profile_sha256="d" * 64,
        claim="REFACTOR_CONTRACT_PRESERVED",
        verification_status="VERIFIED")
    request_id = request["approval"]["request_id"]
    record_human_decision(
        root, request_id, decision="approve", signing_key=reviewer,
        gpg_home=reviewer_home)
    result = service.execute(request_id)

    assert result["status"] == "SIGNED"
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["verification"]["claim_upgraded_by_signing"] is False
    assert result["approval"]["private_key_exposed"] is False
    signature = Path(result["signature"]["path"])
    independent = subprocess.run([
        "gpg", "--homedir", str(public_home), "--batch", "--verify",
        str(signature), str(artifact),
    ], capture_output=True, text=True)
    assert independent.returncode == 0, independent.stderr
