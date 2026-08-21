# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
import shutil
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.rcu_verification import verify_rcu_bounded


ARTIFACT = Path("examples/formalkernel/kernel/scheduler/rcu.json")


@pytest.mark.skipif(shutil.which("esbmc") is None, reason="esbmc not installed")
def test_real_tlaps_and_esbmc_prove_scoped_rcu_safety():
    verdict = verify_rcu_bounded(ARTIFACT)
    assert verdict["status"] == "RCU_RECLAMATION_SAFETY_PROVED"
    assert verdict["judge"] == "tlapm+esbmc"
    assert verdict["scope"] == "parameterized_grace_period_invariant"
    assert verdict["tlaps_obligations_proved"] == 10
    assert verdict["parameterized_grace_period_proved"] is True
    assert verdict["bounded_readers"] == 2
    assert verdict["context_bound"] == 3
    assert verdict["implementation_refinement_proved"] is False
    assert len(verdict["proof_sha256"]) == 64
    assert len(verdict["source_sha256"]) == 64


def test_untrusted_parameterized_proof_reference_fails_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["parameterized_proof"] = "missing.tla"
    drifted = tmp_path / "rcu.json"
    drifted.write_text(json.dumps(artifact))
    assert verify_rcu_bounded(drifted)["code"] == "RCU_ARTIFACT_INVALID"


def test_m71_registry_locks_refinement_and_interrupt_claims():
    milestone = capability("m71_parameterized_rcu").milestone
    assert milestone is not None
    assert milestone.required_judges == ("TLAPS", "ESBMC")
    assert milestone.current_step == 1
    assert milestone.maturity_requires_step == 2
    assert milestone.completed_claims == ("RCU_RECLAMATION_SAFETY_PROVED",)
    assert "RCU_IMPLEMENTATION_REFINEMENT_PROVED" in milestone.claims_forbidden
    assert "RCU_IRQ_NMI_SAFETY_PROVED" in milestone.claims_forbidden
