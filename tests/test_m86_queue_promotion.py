# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from pipeline import cli
from pipeline.virtio_queue_promotion import promote_virtio_queue_model


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "examples/formalkernel/kernel/verus_virtio"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_root(tmp_path: Path) -> Path:
    destination = tmp_path / "examples/formalkernel/kernel/verus_virtio"
    destination.mkdir(parents=True)
    for name in (
        "queue_model.candidate.json", "queue_model.validation.json",
        "virtio_blk_overlay.rs", "functional_evidence.json",
    ):
        shutil.copy2(SOURCE_DIR / name, destination / name)
    production = tmp_path / "examples/formalkernel/kernel/vfs/virtio_blk.rs"
    production.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "examples/formalkernel/kernel/vfs/virtio_blk.rs", production)
    return tmp_path


def test_queue_promotion_parser_requires_explicit_hash():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["promote-queue-model"])
    args = parser.parse_args([
        "promote-queue-model", "--accept-candidate-sha256", "a" * 64])
    assert args.accept_candidate_sha256 == "a" * 64


def test_queue_promotion_rejects_wrong_candidate_hash(tmp_path):
    root = _fixture_root(tmp_path)
    with pytest.raises(ValueError, match="candidate hash mismatch"):
        promote_virtio_queue_model(root, accept_candidate_sha256="0" * 64)
    assert not (root / "examples/formalkernel/kernel/verus_virtio/"
                "queue_model.reviewed.json").exists()


def test_queue_promotion_replays_judge_and_mints_narrow_claim(monkeypatch, tmp_path):
    root = _fixture_root(tmp_path)
    calls = []

    def fake_run(source):
        calls.append(source)
        positive = source.name == "virtio_blk_overlay.rs"
        payload = {"verification-results": {
            "verified": 7 if positive else 0,
            "errors": 0 if positive else 1,
        }}
        return subprocess.CompletedProcess(
            args=["verus"], returncode=0 if positive else 1,
            stdout=json.dumps(payload),
            stderr="" if positive else "postcondition not satisfied") , payload

    monkeypatch.setattr("pipeline.virtio_queue_promotion._run_verus", fake_run)
    candidate = root / "examples/formalkernel/kernel/verus_virtio/queue_model.candidate.json"
    evidence = promote_virtio_queue_model(
        root, accept_candidate_sha256=_sha256(candidate))
    reviewed_path = root / evidence["reviewed_model"]
    reviewed = json.loads(reviewed_path.read_text())
    assert reviewed["human_review"] == {
        "accepted": True,
        "accepted_candidate_sha256": _sha256(candidate),
    }
    assert evidence["claim"] == "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED"
    assert evidence["scope"] == "production_virtio_blk_queue_accounting"
    assert evidence["anti_vacuity"]["executed"] == 6
    assert evidence["anti_vacuity"]["rejected"] == 6
    assert len(calls) == 7
    assert "EXTERNAL_IO_SAFETY_PROVED" in evidence["claims_locked"]
