# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.3 exact Sv39 descriptor/walker correspondence and isolation."""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.riscv_sv39 import verify_sv39_evidence, verify_sv39_isolation
from pipeline.riscv_sv39_promotion import promote_riscv_sv39_plan

ROOT = Path(__file__).parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _mutated(_tmp_path: Path, mutate) -> dict:
    artifact = _json(KERNEL / "riscv_sv39.json")
    plan = _json(KERNEL / "riscv_sv39_plan.json")
    mutate(plan)
    plan["status"] = "REVIEWED_RISCV_SV39_MAPPING_PLAN"
    with tempfile.TemporaryDirectory(prefix="m91-sv39-", dir=ROOT) as directory:
        path = Path(directory) / "plan.json"
        raw = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
        path.write_bytes(raw)
        artifact["mapping_plan"] = {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        return verify_sv39_isolation(artifact, ROOT)


def test_promoted_sv39_evidence_is_bound_to_reviewed_plan_and_transition():
    artifact = _json(KERNEL / "riscv_sv39.json")
    evidence = _json(KERNEL / artifact["validation"])
    verdict = verify_sv39_evidence(artifact, ROOT, evidence)
    assert verdict["status"] == "RISCV_SV39_EVIDENCE_BOUND"
    assert evidence["scope"] == "reviewed_qemu_virt_sv39_descriptor_and_walk_model"
    assert len(evidence["mappings_checked"]) == 5
    assert evidence["hardware_page_walk_proved"] is False
    assert evidence["tlb_coherence_proved"] is False
    assert evidence["compiled_mmu_refinement_proved"] is False
    assert evidence["physical_spatial_isolation_proved"] is False


def test_sv39_rejects_kernel_u_bit_and_user_wx(tmp_path):
    def kernel_u(plan):
        entry = plan["tables"][2]["entries"][0]
        entry["flags"]["U"] = True
        entry["encoded"] += 16
        plan["mappings"][0]["permissions"]["U"] = True
    assert _mutated(tmp_path, kernel_u)["code"] == "RISCV_KERNEL_PAGE_USER_ACCESSIBLE"

    def user_wx(plan):
        entry = plan["tables"][4]["entries"][1]
        entry["flags"]["X"] = True
        entry["encoded"] += 8
        plan["mappings"][3]["permissions"]["X"] = True
    assert _mutated(tmp_path, user_wx)["code"] == "RISCV_USER_WX_VIOLATION"

    def clear_user_text_x(plan):
        entry = plan["tables"][4]["entries"][0]
        entry["flags"]["X"] = False
        entry["encoded"] -= 8
    assert _mutated(tmp_path, clear_user_text_x)["code"] == \
        "RISCV_WALK_PLAN_CORRESPONDENCE_FAILED"


def test_sv39_rejects_protected_redirect_wrong_ppn_and_wrong_satp(tmp_path):
    def redirect(plan):
        entry = plan["tables"][4]["entries"][0]
        entry["ppn"] = 0x80200
        entry["encoded"] = (0x80200 << 10) | 91
        plan["mappings"][2]["pa"] = 0x80200000
    assert _mutated(tmp_path, redirect)["code"] == "RISCV_USER_MAPPING_PROTECTED_FRAME"

    def wrong_intermediate(plan):
        plan["tables"][3]["entries"][0]["ppn"] += 1
    assert _mutated(tmp_path, wrong_intermediate)["code"] == \
        "RISCV_DECLARED_MAPPING_UNRESOLVED"

    def wrong_satp(plan):
        plan["satp"] += 1
    assert _mutated(tmp_path, wrong_satp)["code"] == "RISCV_SATP_ROOT_MISMATCH"


def test_sv39_rejects_guard_mapping_and_noncanonical_acceptance(tmp_path):
    def map_guard(plan):
        plan["tables"][4]["entries"].append(copy.deepcopy(
            plan["tables"][4]["entries"][1]))
        plan["tables"][4]["entries"][-1]["index"] = 2
    assert _mutated(tmp_path, map_guard)["code"] == "RISCV_GUARD_REGION_MAPPED"

    def claim_canonical_invalid(plan):
        plan["invalid_virtual_addresses"][0] = 0x400000
    assert _mutated(tmp_path, claim_canonical_invalid)["code"] == \
        "RISCV_NONCANONICAL_ADDRESS_ACCEPTED"


def test_sv39_transition_dependency_and_registry_scope_fail_closed():
    artifact = _json(KERNEL / "riscv_sv39.json")
    artifact["transition_evidence"]["sha256"] = "0" * 64
    assert verify_sv39_isolation(artifact, ROOT)["claim"] == "NO_PROOF"
    lane = capability("m91_1_riscv_platform_feasibility").milestone
    assert lane is not None and lane.current_step >= 3
    assert lane.current_step >= 3
    assert "RISCV_SPATIAL_ISOLATION_PROVED" in lane.completed_claims
    for forbidden in ("RISCV_HARDWARE_PAGE_WALK_PROVED", "RISCV_TLB_COHERENCE_PROVED",
                      "RISCV_COMPILED_MMU_REFINEMENT_PROVED",
                      "RISCV_PHYSICAL_SPATIAL_ISOLATION_PROVED"):
        assert forbidden in lane.claims_forbidden


def test_sv39_promotion_is_human_only_and_refuses_wrong_hash():
    try:
        promote_riscv_sv39_plan(ROOT, accept_candidate_sha256="0" * 64)
    except ValueError as exc:
        assert "candidate hash mismatch" in str(exc)
    else:
        raise AssertionError("wrong candidate hash was accepted")
    spec = capability("promote_riscv_sv39_plan")
    assert spec.trust_action is True
    assert spec.mcp_tool is None
