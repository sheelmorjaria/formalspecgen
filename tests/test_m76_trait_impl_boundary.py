# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path


ROOT = Path("examples/formalkernel/kernel/refinement")
BOUNDARY = ROOT / "refinedrust_trait_impl_boundary"
LEDGER = ROOT / "refinedrust_boundary_ledger.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_trait_impl_control_and_generic_reproducer_are_hash_bound():
    evidence = json.loads((BOUNDARY / "evidence.json").read_text())
    assert evidence["claim"] == "NO_PROOF"
    assert evidence["control"]["source_sha256"] == _sha(
        BOUNDARY / "control/src/lib.rs")
    assert evidence["minimal_reproducer"]["source_sha256"] == _sha(
        BOUNDARY / "reproducer/src/lib.rs")
    assert evidence["control"]["rocq_build"] == "passed"
    assert evidence["minimal_reproducer"]["rocq_build"] == "passed"
    assert evidence["initial_ice"]["stack_sha256"] == _sha(
        BOUNDARY / "initial_ice.txt")
    assert evidence["local_trait_patch_added"] is False


def test_reproducer_registers_the_impl_and_corrects_initial_ice_diagnosis():
    evidence = json.loads((BOUNDARY / "evidence.json").read_text())
    source = (BOUNDARY / "reproducer/src/lib.rs").read_text()
    assert "#[rr::verify]\nimpl<P> Complete for Adapter<P>" in source
    assert evidence["initial_ice"]["upstream_bug_confirmed"] is False
    assert "omitted rr::verify" in evidence["initial_ice"]["cause"]
    assert evidence["exact_virtio_followup"]["boundary"] == "result_try_branch"


def test_boundary_ledger_distinguishes_qualified_and_open_surfaces():
    ledger = json.loads(LEDGER.read_text())
    indexed = {item["id"]: item for item in ledger["boundaries"]}
    assert ledger["claim"] == "NO_PROOF"
    assert indexed["embedded_array_place_rfn"]["status"] == "CLOSED_LOCALLY"
    assert indexed["generic_local_trait_impl_registration"]["status"] == (
        "QUALIFIED_SUPPORTED")
    assert indexed["result_try_branch"]["status"] == "OPEN"
    assert indexed["named_const_array_len"]["status"] == "OPEN"
    assert indexed["iterator_enumerate_lowering"]["status"] == "OPEN"
    assert indexed["slice_get_mut_trait_semantics"]["status"] == "OPEN"


def test_u1_keeps_all_implementation_refinement_claims_locked():
    evidence = json.loads((BOUNDARY / "evidence.json").read_text())
    assert evidence["primitive_implementation_refinement_proved"] is False
    assert evidence["rust_implementation_refinement_proved"] is False
    assert evidence["compiler_refinement_chain_proved"] is False
    assert evidence["end_to_end_refinement_chain_established"] is False
