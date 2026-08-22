# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
import shutil
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.refinement_spine import verify_refinement_spine

ARTIFACT = Path("examples/formalkernel/kernel/refinement_spine.json")


@pytest.mark.skipif(shutil.which("rustc") is None, reason="rustc not installed")
def test_vfs_vertical_artifacts_are_bound_without_semantic_overclaim():
    verdict = verify_refinement_spine(ARTIFACT)
    assert verdict["status"] == "BOUNDED_COMPILED_REFINEMENT_VALIDATED"
    assert verdict["operations_observed_in_ir"] == ["close", "new", "open", "read", "write"]
    assert verdict["semantic_ir_refinement_proved"] is False
    assert verdict["verified_compiler_proved"] is False
    assert verdict["valid_states_checked"] == 255
    assert verdict["operation_transitions_checked"] == 1020
    assert verdict["end_to_end_refinement_chain_established"] is False
    assert all(len(verdict[name]) == 64 for name in
               ("model_sha256", "rust_source_sha256", "llvm_ir_sha256", "object_sha256"))


def test_end_to_end_overclaim_is_rejected():
    artifact = json.loads(ARTIFACT.read_text())
    artifact["end_to_end_refinement_chain_established"] = True
    path = ARTIFACT.parent / "refinement_spine.test.json"
    try:
        path.write_text(json.dumps(artifact))
        assert verify_refinement_spine(path)["code"] == "REFINEMENT_SPINE_EPISTEMIC_BOUNDARY_INVALID"
    finally:
        path.unlink(missing_ok=True)


def test_registry_mints_only_array_translation_at_foundational_step():
    milestone = capability("m76_semantic_refinement_spine").milestone
    assert milestone is not None
    assert milestone.current_step == 3 and milestone.step_status == "partial"
    assert milestone.completed_claims == ("REFINEMENT_CHAIN_ARTIFACTS_BOUND",
                                          "BOUNDED_COMPILED_REFINEMENT_VALIDATED",
                                          "REFINEDRUST_ARRAY_TRANSLATION_VALIDATED")
    assert "VERIFIED_COMPILER_PROVED" in milestone.claims_forbidden
    locked = {item.claim for item in milestone.claims
              if item.claim not in milestone.completed_claims}
    assert "RUST_IMPLEMENTATION_REFINEMENT_PROVED" in locked
    assert "COMPILER_REFINEMENT_CHAIN_PROVED" in locked
    assert "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED" in locked
