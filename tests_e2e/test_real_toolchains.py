import json
from pathlib import Path

import pytest

from pipeline.c_support import verify_framac
from pipeline.implementation import synthesize_implementation
from pipeline.jml_to_dafny import translate_and_verify
from pipeline.tla_backend import generate_and_check
from pipeline.verify import classify, has_dropped_vc, verify
from pipeline.domain_v2 import DomainSpecV2
from pipeline.v2_jml_serializer import render_class

from fixtures import ACSL, BANKING, COUNTER, LINKED, TRUSTED_COUNTER_STUB


pytestmark = pytest.mark.toolchain


def test_openjml_esc_and_native_verdict_are_real(openjml_tool, tmp_path):
    source = tmp_path / "Counter.java"
    source.write_text(COUNTER, encoding="utf-8")
    exit_code, output = verify(source, mode="esc")
    assert classify(exit_code) == "VERIFIED", output
    assert not has_dropped_vc(output), output

    run = tmp_path / "implementation"
    result = synthesize_implementation(
        TRUSTED_COUNTER_STUB, candidate=COUNTER, out_dir=run, max_attempts=1)
    verdict = json.loads((run / "verdict.json").read_text(encoding="utf-8"))
    assert result["final_status"] == verdict["final_status"] == "VERIFIED"
    assert verdict["claim"] == "DEDUCTIVE_PROOF"
    assert verdict["native_synthesis"] is True
    assert verdict["external_handoff_used"] is False
    assert verdict["attempts"][0]["candidate_hash"]
    assert verdict["trusted_contract_hash"]


def test_dafny_linked_boundary_is_really_verified(dafny_tool):
    result = translate_and_verify(LINKED)
    assert result.status == "VERIFIED", result.output
    assert result.translation.boundary == "linked_reachability"
    assert "0 errors" in result.output


def test_tlc_banking_model_is_really_checked(tlc_tool):
    result = generate_and_check(
        BANKING, clarifications="Operations are linearizable and atomic. Account identity is immutable.",
        abstraction="atomic_operations")
    assert result["status"] == "VERIFIED", result.get("output")
    assert result["claim"] == "BOUNDED_ARCHITECTURE_EVIDENCE"
    assert result["source_refinement_proved"] is False
    assert result["renderer"] == "bank_account_atomic_operations_v1"


def test_framac_wp_is_really_verified_with_scoped_rte_claim(framac_tools):
    result = verify_framac(ACSL)
    assert result["status"] == "VERIFIED", result.get("output")
    assert result["claim"] == "DEDUCTIVE_PROOF"
    assert result["proved_goals"] == result["total_goals"] > 0
    assert result["runtime_errors"] in {"GENERATED", "PARTIAL"}


def test_v2_jml_serializer_output_is_really_openjml_checked(openjml_tool, tmp_path):
    value = {
        "schema_version": 2, "domain_name": "Switch", "module_name": "switch",
        "state_variables": [{"kind": "bool", "name": "enabled", "initial": False}],
        "operations": [{"name": "Enable", "return_type": "void",
            "failure_semantics": "unavailable", "guards": [],
            "effects": [{"id": "set_enabled", "target": "enabled",
                         "value": {"kind": "boolean", "value": True}}],
            "frame": ["enabled"]}],
        "tlc_invariants": [{"id": "EnabledTyped", "expression": {
            "kind": "or", "left": {"kind": "field", "name": "enabled"},
            "right": {"kind": "eq", "left": {"kind": "field", "name": "enabled"},
                      "right": {"kind": "boolean", "value": False}}}}],
    }
    source = tmp_path / "Switch.java"
    source.write_text(render_class(DomainSpecV2.model_validate(value)), encoding="utf-8")
    exit_code, output = verify(source, mode="check")
    assert classify(exit_code) == "VERIFIED", output
