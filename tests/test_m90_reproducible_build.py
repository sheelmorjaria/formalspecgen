# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.reproducible_build import observe_reproducibility


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
CONFIG = KERNEL / "m90_build_config.json"
BINARY_EVIDENCE = KERNEL / "m90_binary_evidence.json"
VALIDATION = KERNEL / "m90_reproducibility.validation.json"
ELF = ROOT / "examples/formalkernel/boot/m90-qemu-aarch64.elf"


def _stored():
    return json.loads(VALIDATION.read_text())


def test_two_clean_builds_and_evidence_roots_reproduce_exactly():
    stored = _stored()
    replay = observe_reproducibility(ROOT, CONFIG, BINARY_EVIDENCE)
    assert replay == stored
    assert stored["status"] == "REPRODUCIBLE_BUILD_OBSERVATION_COMPLETE"
    assert stored["claims_minted"] == [
        "REPRODUCIBLE_BINARY_BUILD_OBSERVED",
        "REPRODUCIBLE_EVIDENCE_ROOT_OBSERVED",
    ]
    assert stored["raw_elf_reproducible"] is True
    assert stored["structural_digest_reproducible"] is True
    assert stored["canonical_evidence_root_reproducible"] is True
    assert stored["observations"][0]["raw_elf_sha256"] == stored["observations"][1][
        "raw_elf_sha256"]
    assert stored["observations"][0]["raw_elf_sha256"] == __import__(
        "hashlib").sha256(ELF.read_bytes()).hexdigest()


def test_raw_binary_identity_is_never_hidden_by_canonicalization():
    stored = _stored()
    assert stored["normalization"]["elf_bytes"] == "NONE"
    assert stored["normalization"]["structural_identity"] == (
        "PARSED_WITHOUT_NORMALIZATION")
    build_id = next(item for item in stored["mutation_results"]
                    if item["case"] == "deliberate_build_id_perturbation")
    assert build_id["actual"] == "RAW_ELF_DIFFERENT"
    assert build_id["passed"] is True


def test_path_timestamp_environment_order_and_tool_mutations_are_explicit():
    results = {item["case"]: item for item in _stored()["mutation_results"]}
    assert results["independent_build_directory"]["passed"] is True
    assert results["file_timestamp_change"]["passed"] is True
    assert results["source_manifest_order"]["passed"] is True
    assert results["locale_timezone_source_date_epoch_injection"][
        "actual_evidence_status"] == "REBUILD_REQUIRED"
    assert results["compiler_identity_change"]["actual"] == "REBUILD_REQUIRED"
    assert results["linker_input_ordering"]["status"] == (
        "NOT_APPLICABLE_SINGLE_RUST_CRATE_NO_EXTERNAL_LINK_INPUT_LIST")
    assert all(item["passed"] for item in results.values())


def test_checked_evidence_contains_no_ephemeral_build_directory():
    raw = VALIDATION.read_text()
    assert "/tmp/m90-repro-" not in raw
    assert "clean_build_a" in raw and "clean_build_b" in raw


def test_m90_4_registry_uses_observed_not_proved_claims():
    milestone = capability("m90_4_reproducible_build_observation").milestone
    assert milestone is not None
    assert milestone.current_step == 4
    assert milestone.completed_claims == (
        "REPRODUCIBLE_BINARY_BUILD_OBSERVED",
        "REPRODUCIBLE_EVIDENCE_ROOT_OBSERVED",
    )
    assert "REPRODUCIBLE_BUILD_PROVED" in milestone.claims_forbidden
