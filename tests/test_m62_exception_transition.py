# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M62: bounded exception-transition proof and honest silicon boundary."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.exception_transition import (render_exception_transition,
                                           verify_exception_evidence,
                                           write_exception_validation)
from pipeline.kernel_lattice import verify_kernel

ROOT = Path(__file__).parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
PROFILES = [ROOT / "examples/formalkernel/profiles/n150.json",
            ROOT / "examples/formalkernel/profiles/r52.json"]


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_published_tlc_evidence_is_hash_bound_and_scoped():
    artifact = _json(KERNEL / "exception_transition.json")
    evidence = _json(KERNEL / artifact["validation"])
    verdict = verify_exception_evidence(artifact, KERNEL, evidence)
    assert verdict["status"] == "EXCEPTION_TRANSITION_EVIDENCE_BOUND"
    assert verdict["distinct_states"] == 6
    assert evidence["hardware_eret_semantics_proved"] is False
    assert evidence["compiled_vector_refinement_proved"] is False


def test_model_contains_privilege_and_dispatch_invariants():
    tla, cfg = render_exception_transition()
    assert "EL0RequiresPreparedReturn" in tla
    assert "TrappedReturnRequiresDispatch" in tla
    assert "ReturnFromSyscall" in tla and "dispatchChecked" in tla
    assert "INVARIANT TrappedReturnRequiresDispatch" in cfg
    with pytest.raises(ValueError, match="EXCEPTION_MODULE_INVALID"):
        render_exception_transition("bad-module")


def test_artifact_or_evidence_drift_fails_closed(tmp_path):
    artifact = _json(KERNEL / "exception_transition.json")
    evidence = _json(KERNEL / artifact["validation"])
    drifted = copy.deepcopy(artifact)
    drifted["bindings"]["mmu"]["sha256"] = "0" * 64
    assert verify_exception_evidence(drifted, KERNEL, evidence)["claim"] == "NO_PROOF"
    bad_evidence = copy.deepcopy(evidence)
    bad_evidence["properties"].remove("TRAPPED_RETURN_REQUIRES_DISPATCH")
    assert verify_exception_evidence(artifact, KERNEL, bad_evidence)["code"] == \
        "EXCEPTION_EVIDENCE_BINDING_MISMATCH"
    with pytest.raises(ValueError, match="PUBLICATION_REFUSED"):
        write_exception_validation(tmp_path / "no.json", {"status": "failed"})


def test_microkernel_mints_model_claim_and_monolith_omits_it():
    micro = verify_kernel(KERNEL, PROFILES)
    claims = [item for item in micro["claims"]
              if item["claim"] == "EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED"]
    assert len(claims) == 1
    assert claims[0]["judge"] == "tlc"
    assert claims[0]["profile"] == "r52"
    assert claims[0]["scope"] == "tlc_aarch64_el1_el0_control_state"
    assert claims[0]["evidence"]["hardware_eret_semantics_proved"] is False
    mono = verify_kernel(KERNEL, PROFILES, "monolith.json")
    assert not any(item["claim"] == "EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED"
                   for item in mono["claims"])
    assert any(item["claim"] == "EXCEPTION_LEVEL_TRANSITION_MODEL_OMITTED"
               for item in mono["boundaries"])


def test_registry_forbids_silicon_and_compiled_vector_claims():
    lane = capability("m62_exception_transition").milestone
    assert lane is not None and lane.required_judges == ("TLC",)
    assert lane.current_maturity == "model-evidence"
    assert "HARDWARE_EXCEPTION_LEVEL_TRANSITION_PROVED" in lane.claims_forbidden
    assert "COMPILED_VECTOR_REFINEMENT_PROVED" in lane.claims_forbidden
    assert lane.hardware_profiles == ("r52",)
