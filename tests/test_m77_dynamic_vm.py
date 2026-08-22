import json
import shutil
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.dynamic_vm import verify_dynamic_vm

ARTIFACT = Path("examples/formalkernel/kernel/dynamic_vm.json")


@pytest.mark.skipif(shutil.which("z3") is None, reason="real Z3 not installed")
def test_symbolic_dynamic_quota_and_numa_invariants_are_inductive():
    verdict = verify_dynamic_vm(ARTIFACT)
    assert verdict["status"] == "VM_RESOURCE_ISOLATION_PROVED"
    assert set(verdict["claims"]) == {"VM_RESOURCE_ISOLATION_PROVED", "NUMA_ACCOUNTING_PROVED"}
    assert verdict["deterministic_exhaustion"] is True
    assert verdict["hardware_tlb_coherence_proved"] is False
    assert len(verdict["smt_sha256"]) == 64


def test_invalid_admission_and_hardware_overclaim_fail_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["admitted_memory_pages"] = 11
    path = tmp_path / "vm.json"; path.write_text(json.dumps(artifact))
    assert verify_dynamic_vm(path)["code"] == "DYNAMIC_VM_ADMISSION_INVALID"
    artifact = json.loads(ARTIFACT.read_text())
    artifact["hardware_tlb_coherence_proved"] = True
    path.write_text(json.dumps(artifact))
    assert verify_dynamic_vm(path)["code"] == "DYNAMIC_VM_EPISTEMIC_BOUNDARY_INVALID"


def test_registry_keeps_physical_and_unbounded_claims_locked():
    milestone = capability("m77_dynamic_vm_numa").milestone
    assert milestone is not None and milestone.step_status == "partial"
    assert "HARDWARE_TLB_COHERENCE_PROVED" in milestone.claims_forbidden
