# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M55 bounded VFS model and hash-bound Deliverable 3 evidence."""
import json
from pathlib import Path

import yaml

from pipeline.capability_registry import capability
from pipeline.domain_v2_model import (
    apply_effects, guards_hold, state_space_upper_bound,
    static_deadlock_findings, validate_transitions_and_invariants,
)
from pipeline.domain_v2_evidence import verify_evidence_envelope
from pipeline.domain_v2_promotion import candidate_sha256, load_candidate
from pipeline.domain_v2_tla import render_v2_tla


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "domains/candidates/vfs.v2.yaml"


def test_vfs_candidate_is_bounded_unreviewed_and_recyclable():
    spec = load_candidate(CANDIDATE)
    assert spec.review_status == "unreviewed"
    assert spec.domain_name == "VfsInodeCache"
    assert [operation.name for operation in spec.operations] == [
        "open", "close", "read", "write"]
    assert {variable.name: getattr(variable, "bound", None)
            for variable in spec.state_variables} == {
                "inode_count": (0, 4), "free_list_head": (0, 4),
                "open_handle_count": (0, 4), "cached_bytes": (0, 16)}
    assert static_deadlock_findings(spec) == []
    assert state_space_upper_bound(spec) == 6375
    assert validate_transitions_and_invariants(spec) == (123, 492)


def test_open_close_preserve_inode_pool_conservation():
    spec = load_candidate(CANDIDATE)
    operations = {operation.name: operation for operation in spec.operations}
    state = {"inode_count": 0, "free_list_head": 4,
             "open_handle_count": 0, "cached_bytes": 0}
    assert guards_hold(operations["open"], state)
    opened = apply_effects(operations["open"], state)
    assert opened["inode_count"] + opened["free_list_head"] == 4
    assert guards_hold(operations["close"], opened)
    assert apply_effects(operations["close"], opened) == state


def test_vfs_renders_and_deliverable_three_unlocks_only_bounded_evidence():
    spec = load_candidate(CANDIDATE)
    tla, cfg = render_v2_tla(spec)
    assert "MODULE VfsInodeCache" in tla
    assert "inode_pool_conservation" in cfg
    validation = CANDIDATE.with_suffix(".validation.json")
    reviewed_path = ROOT / "domains/v2/vfs.json"
    envelope = json.loads(validation.read_text())
    reviewed = json.loads(reviewed_path.read_text())
    digest = candidate_sha256(spec)
    assert verify_evidence_envelope(envelope)
    assert envelope["evidence"]["candidate_sha256"] == digest
    assert envelope["evidence"]["validation_status"] == "VALIDATED"
    assert envelope["evidence"]["reachable_state_count"] == 123
    assert envelope["evidence"]["reachable_transition_count"] == 492
    assert reviewed["review_status"] == "reviewed"
    assert reviewed["accepted_candidate_sha256"] == digest
    assert reviewed["accepted_evidence_sha256"] == envelope["evidence_sha256"]
    lane = capability("m55_vfs").milestone
    assert lane is not None and lane.current_step == 4
    assert lane.step_status == "complete"
    assert lane.current_maturity == "production"
    assert lane.maturity_from == "scaffold"
    assert lane.completed_claims == (
        "BOUNDED_ARCHITECTURE_EVIDENCE", "SOURCE_MODEL_REFINEMENT",
        "HARDWARE_MEMORY_BOUND_PROVED")
    assert [claim.claim for claim in lane.claims
            if claim.claim not in lane.completed_claims] == []
    assert "HARDWARE_MEMORY_BOUND_PROVED_WITHOUT_PROFILE_BOUND_POOL" in \
        lane.claims_forbidden


def test_vfs_native_refinement_and_hardware_pool_are_production_bound():
    evidence = yaml.safe_load((ROOT / "domains/v2/vfs_bounded.rust-refinement.yaml")
                              .read_text())
    rust = (ROOT / "Vfs.rs").read_text()
    assert evidence["status"] == "VERIFIED"
    assert evidence["claims"] == [
        "SOURCE_MODEL_REFINEMENT", "HARDWARE_MEMORY_BOUND_PROVED"]
    assert evidence["judge"]["verified_items"] == 9
    assert {item["operation"] for item in evidence["obligations"]} == {
        "open", "close", "read", "write"}
    assert evidence["hardware_judge"]["result"] == "VERIFIED"
    assert evidence["hardware_judge"]["memory_footprint_bytes"] == 64
    assert evidence["static_pool_materialized"] is True
    assert evidence["locked_claims"] == []
    assert "slots: [bool; 4]" in rust
