# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.proof_carrying_binary import (
    CLAIM,
    build_binary_evidence,
    validate_binary_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
CONFIG = KERNEL / "m90_build_config.json"
PREBUILD = KERNEL / "m90_evidence_root.candidate.json"
BUNDLE = KERNEL / "m90_kernel_evidence_bundle.json"
EVIDENCE = KERNEL / "m90_binary_evidence.json"
ELF = ROOT / "examples/formalkernel/boot/m90-qemu-aarch64.elf"


def _evidence():
    return json.loads(EVIDENCE.read_text())


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exact_target_elf_build_and_evidence_are_replayable():
    stored = _evidence()
    regenerated = build_binary_evidence(ROOT, CONFIG, PREBUILD, BUNDLE, ELF)
    assert regenerated == stored
    assert validate_binary_evidence(stored, ROOT) == {
        "status": CLAIM, "claim": CLAIM,
        "scope": "qemu_aarch64_elf_artifact_identity_and_applicable_evidence_closure",
        "elf_sha256": stored["elf"]["sha256"], "applicable_claims": 2,
    }
    assert [item["claim"] for item in stored["applicable_claims"]] == [
        "SYSTEM_COMPOSITION_PROVED", "RUST_WITNESS_REFINEMENT_PROVED"]
    assert stored["release_seal_status"] == "HUMAN_SEAL_PENDING"


def test_elf_byte_substitution_and_target_identity_fail_closed(tmp_path):
    changed = _evidence()
    substituted = tmp_path / "substituted.elf"
    raw = bytearray(ELF.read_bytes())
    raw[-1] ^= 1
    substituted.write_bytes(raw)
    changed["elf"]["path"] = str(substituted)
    assert validate_binary_evidence(changed, ROOT)["status"] == "M90_ELF_IDENTITY_MISMATCH"

    architecture = _evidence()
    architecture["elf"]["identity"]["machine"] = "x86-64"
    assert validate_binary_evidence(architecture, ROOT)["status"] == (
        "M90_ELF_STRUCTURE_MISMATCH")


def test_wrong_profile_codegen_and_linker_provenance_are_rejected():
    profile = _evidence()
    desktop = KERNEL / "desktop.json"
    profile["build_record"]["deployment_manifest"] = {
        "path": desktop.relative_to(ROOT).as_posix(), "sha256": _sha(desktop)}
    assert validate_binary_evidence(profile, ROOT)["status"] == "M90_BUILD_PROFILE_MISMATCH"

    optimization = _evidence()
    invocation = optimization["build_record"]["invocation"]
    invocation[invocation.index("-Copt-level=0")] = "-Copt-level=3"
    assert validate_binary_evidence(optimization, ROOT)["status"] == (
        "M90_BUILD_PROVENANCE_MISMATCH")

    linker = _evidence()
    linker["build_record"]["linker"]["sha256"] = "0" * 64
    assert validate_binary_evidence(linker, ROOT)["status"] == (
        "M90_BUILD_TOOL_REPLAY_REQUIRED")


def test_source_and_applicable_claim_closure_cannot_be_weakened_or_inflated():
    source = _evidence()
    source["build_record"]["compiled_sources"].pop()
    assert validate_binary_evidence(source, ROOT)["status"] == (
        "M90_BUILD_SOURCE_CLOSURE_INVALID")

    omitted = _evidence()
    omitted["applicable_claims"].pop()
    assert validate_binary_evidence(omitted, ROOT)["status"] == (
        "M90_APPLICABILITY_CLOSURE_MISMATCH")

    inflated = _evidence()
    fabricated = copy.deepcopy(inflated["applicable_claims"][0])
    fabricated["claim"] = "SPATIAL_ISOLATION_PROVED"
    inflated["applicable_claims"].append(fabricated)
    assert validate_binary_evidence(inflated, ROOT)["status"] == (
        "M90_APPLICABILITY_CLOSURE_MISMATCH")

    pending = _evidence()
    pending["applicable_claims"][0]["claim"] = "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"
    assert validate_binary_evidence(pending, ROOT)["status"] == (
        "M90_APPLICABILITY_CLOSURE_MISMATCH")


def test_stale_review_or_model_dependency_and_dag_substitution_are_rejected():
    dependency = _evidence()
    dependency["applicable_claims"][0]["dependencies"][0]["sha256"] = "0" * 64
    assert validate_binary_evidence(dependency, ROOT)["status"] == (
        "M90_BINARY_DEPENDENCY_STALE")

    dag = _evidence()
    dag["evidence_dag"]["root_digest"] = "0" * 64
    assert validate_binary_evidence(dag, ROOT)["status"] == "M90_EVIDENCE_DAG_STALE"


def test_m90_2_registry_mints_only_identity_binding_claim():
    milestone = capability("m90_2_target_elf_evidence_binding").milestone
    assert milestone is not None
    assert milestone.current_step == 2
    assert milestone.current_maturity == "proof-carrying-binary"
    assert milestone.completed_claims == (CLAIM,)
    assert "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED" in milestone.claims_forbidden
    assert "TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED" in milestone.claims_forbidden
