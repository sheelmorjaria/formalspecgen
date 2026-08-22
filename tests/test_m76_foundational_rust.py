# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path

from pipeline.foundational_rust_subset import verify_foundational_rust_subset

SUBSET = Path("examples/formalkernel/kernel/foundational_rust_subset.json")
SMOKE = Path("examples/formalkernel/kernel/refinedrust_smoke")
ALLOCATOR_FEASIBILITY = Path(
    "examples/formalkernel/kernel/refinement/m76_3b_allocator_feasibility.json")
ARRAY_REGRESSION = Path(
    "examples/formalkernel/kernel/refinement/refinedrust_array_regression")
ARRAY_PATCH = Path(
    "examples/formalkernel/kernel/refinement/patches/"
    "refinedrust-0.1.0-array-place-rfn.patch")
ALLOCATOR_REFINEMENT = Path(
    "examples/formalkernel/kernel/refinement/refinedrust_allocator")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_abstract_rocq_obligations_do_not_overclaim_rust_refinement():
    verdict = verify_foundational_rust_subset(SUBSET)
    assert verdict["status"] in {
        "FOUNDATIONAL_RUST_SUBSET_SEMANTICS_CHECKED", "judge_pending"}
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["rust_model_functional_refinement_proved"] is False
    assert verdict["end_to_end_refinement_chain_established"] is False


def test_refinedrust_smoke_evidence_binds_translation_and_proof():
    evidence = json.loads((SMOKE / "evidence.json").read_text())
    generated = SMOKE / "output/formalkernel_refinedrust_smoke"
    assert evidence["claim"] == "NO_PROOF"
    assert evidence["source_sha256"] == _sha(SMOKE / "src/lib.rs")
    assert evidence["generated_code_sha256"] == _sha(
        generated / "generated/generated_code_formalkernel_refinedrust_smoke.v")
    assert evidence["generated_specs_sha256"] == _sha(
        generated / "generated/generated_specs_formalkernel_refinedrust_smoke.v")
    assert evidence["generated_template_sha256"] == _sha(
        generated / "generated/generated_template_preserve.v")
    assert evidence["proof_sha256"] == _sha(generated / "proofs/proof_preserve.v")
    assert evidence["anti_vacuity"]["observed_result"] == "ROCQ_INCOMPLETE_PROOF"
    assert evidence["rust_implementation_refinement_proved"] is False


def test_allocator_feasibility_names_blocker_without_substituting_a_copy():
    evidence = json.loads(ALLOCATOR_FEASIBILITY.read_text())
    source = Path("examples/formalkernel/kernel") / evidence["production_source"]
    assert evidence["production_source_sha256"] == _sha(source)
    assert evidence["status"] == "judge_pending"
    assert evidence["claim"] == "NO_PROOF"
    assert evidence["bounded_allocator_implementation_refinement_proved"] is False
    assert {item["result"] for item in evidence["feasibility_results"]} == {
        "FRONTEND_TYPE_TRANSLATION_REJECTED",
        "PROOF_SEARCH_DID_NOT_COMPLETE_WITHIN_BOUNDED_ATTEMPT",
    }


def test_refinedrust_array_patch_is_generic_and_hash_bound():
    evidence = json.loads((ARRAY_REGRESSION / "evidence.json").read_text())
    source = Path("examples/formalkernel/kernel/user/heap.rs")
    assert evidence["claim"] == "REFINEDRUST_ARRAY_TRANSLATION_VALIDATED"
    assert evidence["regression_lengths"] == [0, 1, 2, 4, 16]
    assert evidence["regression_suite_sha256"] == _sha(
        ARRAY_REGRESSION / "src/lib.rs")
    assert evidence["judge"]["local_patch_sha256"] == _sha(ARRAY_PATCH)
    assert evidence["production_allocator_sha256"] == _sha(source)
    assert evidence["production_allocator_modified"] is False
    patch = ARRAY_PATCH.read_text()
    assert "Self::Array(ty, _)" in patch
    assert "PlaceRfn" in patch
    assert "Slots16" not in patch
    assert "occupied" not in patch


def test_embedded_array_translation_matches_array_semantics_for_matrix():
    evidence = json.loads((ARRAY_REGRESSION / "evidence.json").read_text())
    generated = ARRAY_REGRESSION / (
        "output/formalkernel_refinedrust_array_regression/generated/"
        "generated_specs_formalkernel_refinedrust_array_regression.v")
    assert evidence["generated_rocq_sha256"] == _sha(generated)
    text = generated.read_text()
    for length in evidence["regression_lengths"]:
        assert f"array_t {length} bool_t" in text
        section = text.split(f"Section Slots{length}_ty.", 1)[1].split(
            f"End Slots{length}_ty.", 1)[0]
        assert "list ((place_rfnRT bool))" in section


def test_malformed_array_translator_was_rejected_by_rocq():
    evidence = json.loads((ARRAY_REGRESSION / "evidence.json").read_text())
    before = json.loads((ARRAY_REGRESSION / "before_fix.json").read_text())
    assert evidence["anti_vacuity"]["before_fix_evidence_sha256"] == _sha(
        ARRAY_REGRESSION / "before_fix.json")
    assert before["embedded_array_generated_refinement_before_fix"] == "list bool"
    assert before["observed_rocq_result"] == "TYPE_MISMATCH_REJECTED"
    assert evidence["anti_vacuity"]["observed_result"] == (
        "ROCQ_TYPE_MISMATCH_REJECTED")
    assert evidence["bounded_allocator_implementation_refinement_proved"] is False
    assert evidence["rust_implementation_refinement_proved"] is False
    assert evidence["compiler_refinement_chain_proved"] is False
    assert evidence["end_to_end_refinement_chain_established"] is False


def test_allocator_overlay_erases_to_exact_production_source():
    evidence = json.loads((ALLOCATOR_REFINEMENT / "feasibility.json").read_text())
    overlay = (ALLOCATOR_REFINEMENT / "src/lib.rs").read_text()
    ghost_prefix = "".join((
        "#![feature(register_tool)]\n",
        "#![register_tool(rr)]\n",
        "#![feature(custom_inner_attributes)]\n",
        "#![rr::package(\"formalkernel_refinedrust_allocator\")]\n",
    ))
    assert overlay.startswith(ghost_prefix)
    erased = overlay.removeprefix(ghost_prefix).replace("    #[rr::verify]\n", "")
    production = Path(evidence["production_source"])
    assert erased.encode() == production.read_bytes()
    assert evidence["production_source_sha256"] == _sha(production)
    assert evidence["ghost_overlay_sha256"] == _sha(
        ALLOCATOR_REFINEMENT / "src/lib.rs")


def test_allocator_refinement_fails_closed_before_mutation_suite():
    evidence = json.loads((ALLOCATOR_REFINEMENT / "feasibility.json").read_text())
    assert evidence["status"] == "judge_pending"
    assert evidence["claim"] == "NO_PROOF"
    assert evidence["dependencies"]["claim"] == (
        "REFINEDRUST_ARRAY_TRANSLATION_VALIDATED")
    assert evidence["dependencies"]["refinedrust_local_patch_sha256"] == _sha(
        ARRAY_PATCH)
    assert {result["gate"] for result in evidence["judge_results"]} == {
        "named_const_array_length",
        "allocation_iterator_pattern",
        "release_slice_indexing",
    }
    assert evidence["mutation_suite_executed"] is False
    assert evidence["bounded_allocator_implementation_refinement_proved"] is False
    assert evidence["rust_implementation_refinement_proved"] is False
    assert evidence["compiler_refinement_chain_proved"] is False
    assert evidence["end_to_end_refinement_chain_established"] is False
