# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from pipeline import cli
from pipeline.information_flow_promotion import promote_information_flow_scope
from pipeline.information_flow import prepare_two_run_judgment


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_root(tmp_path: Path) -> Path:
    destination = tmp_path / "examples/formalkernel/kernel"
    destination.mkdir(parents=True)
    for name in (
        "m88_information_flow_scope.candidate.json", "server_capabilities.json",
        "syscalls.json", "ipc.json",
    ):
        shutil.copy2(KERNEL / name, destination / name)
    return tmp_path


def test_scope_promotion_cli_requires_an_explicit_hash():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["promote-information-flow-scope"])
    args = parser.parse_args([
        "promote-information-flow-scope",
        "--accept-candidate-sha256", "a" * 64])
    assert args.accept_candidate_sha256 == "a" * 64


def test_scope_promotion_rejects_hash_mismatch_without_writing(tmp_path):
    root = _fixture_root(tmp_path)
    with pytest.raises(ValueError, match="candidate hash mismatch"):
        promote_information_flow_scope(root, accept_candidate_sha256="0" * 64)
    assert not (root / "examples/formalkernel/kernel/"
                "m88_information_flow_scope.reviewed.json").exists()


def test_scope_promotion_freezes_review_without_minting_proof(tmp_path):
    root = _fixture_root(tmp_path)
    candidate = root / "examples/formalkernel/kernel/"
    candidate /= "m88_information_flow_scope.candidate.json"
    result = promote_information_flow_scope(
        root, accept_candidate_sha256=_sha256(candidate))
    reviewed_path = root / result["reviewed_scope"]
    reviewed = json.loads(reviewed_path.read_text())
    assert result["status"] == "INFORMATION_FLOW_SCOPE_PROMOTED"
    assert result["claim"] == "NO_PROOF"
    assert reviewed["status"] == "REVIEWED_HYPERPROPERTY_SCOPE"
    assert reviewed["claim"] == "NO_PROOF"
    assert reviewed["accepted_candidate_sha256"] == _sha256(candidate)
    assert reviewed["two_run_judgment_executed"] is False
    assert reviewed["confidentiality_mutation_rejected"] is False
    prepared = prepare_two_run_judgment(reviewed_path)
    assert prepared["status"] == "SELF_COMPOSITION_NOT_EXECUTED"
    assert prepared["claim"] == "NO_PROOF"
    assert prepared["reviewed_scope_sha256"] == _sha256(reviewed_path)


def test_two_run_gate_refuses_candidate_scope():
    prepared = prepare_two_run_judgment(
        KERNEL / "m88_information_flow_scope.candidate.json")
    assert prepared["status"] == "REVIEWED_SCOPE_REQUIRED"
    assert prepared["claim"] == "NO_PROOF"
    assert prepared["code"] == "M88_SCOPE_NOT_HASH_ACCEPTED"
