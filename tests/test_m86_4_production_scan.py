# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pipeline.implementation_bridge import ImplementationBridgeEvidence


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "examples/formalkernel/kernel/verus_m86_4_feasibility.json"
GOLDEN = ROOT / "examples/formalkernel/kernel/verus_virtio/bridge_contract.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_m86_4_scan_refuses_to_invent_a_second_production_module():
    report = json.loads(REPORT.read_text())
    assert report["status"] == "PARKED_NO_ELIGIBLE_PRODUCTION_MODULE"
    assert report["claim"] == "NO_PROOF"
    assert report["scan_status"] == "complete"
    assert report["selected_candidate"] is None
    assert all(not item["production_rust_found"]
               for item in report["preferred_targets"])
    for item in report["existing_rust_assessment"]:
        assert item["source_sha256"] == _sha256(ROOT / item["source"])
        assert item["eligible"] is False
    assert "SECOND_MODULE_MODEL_BRIDGE_PROVED" in report["claims_locked"]
    assert report["reopen_when"] == [
        "production_state_transition_exists",
        "safe_rust_supported_fragment",
        "meaningful_semantic_contract",
        "negative_mutation_possible",
    ]


def test_promoted_virtio_bridge_is_the_common_contract_golden_fixture():
    envelope = ImplementationBridgeEvidence.model_validate_json(GOLDEN.read_text())
    directory = GOLDEN.parent
    assert envelope.bridge_status == "PROVED"
    assert envelope.model_candidate_sha256 == _sha256(
        directory / "queue_model.candidate.json")
    assert envelope.reviewed_model_sha256 == _sha256(
        directory / "queue_model.reviewed.json")
    assert envelope.overlay_sha256 == _sha256(directory / "virtio_blk_overlay.rs")
    assert envelope.production_source_sha256 == _sha256(
        ROOT / "examples/formalkernel/kernel/vfs/virtio_blk.rs")


def test_common_bridge_schema_requires_nonvacuity_and_review_for_proof():
    base = {
        "implementation_claim": "EXAMPLE_IMPLEMENTATION_CORRECTNESS_PROVED",
        "model_candidate_sha256": "a" * 64,
        "model_review_status": "reviewed",
        "reviewed_model_sha256": "b" * 64,
        "overlay_sha256": "c" * 64,
        "production_source_sha256": "d" * 64,
        "verification_units": 2,
        "semantic_obligations": 4,
        "mutations": {"executed": 2, "rejected": 2},
        "bridge_status": "PROVED",
        "trusted_assumptions": ["judge binary matches its recorded hash"],
        "forbidden_claims": ["END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"],
    }
    assert ImplementationBridgeEvidence.model_validate(base).bridge_status == "PROVED"
    with pytest.raises(ValidationError):
        ImplementationBridgeEvidence.model_validate(
            base | {"model_review_status": "candidate", "reviewed_model_sha256": None})
    with pytest.raises(ValidationError):
        ImplementationBridgeEvidence.model_validate(
            base | {"mutations": {"executed": 2, "rejected": 1}})
