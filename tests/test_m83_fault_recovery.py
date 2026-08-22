import json
from pathlib import Path

from pipeline.fault_recovery import verify_fault_recovery
from pipeline.capability_registry import capability


ARTIFACT = Path("examples/formalkernel/kernel/fault_recovery.json")


def test_faults_reach_scoped_recovery_and_poison_is_removed():
    verdict = verify_fault_recovery(ARTIFACT)
    assert verdict["status"] == "FAULT_CONTAINMENT_RECOVERY_PROVED"
    assert verdict["poison_accounting_proved"] is True
    assert verdict["supervisor_survival_proved"] is True
    assert verdict["physical_mce_semantics_proved"] is False


def test_bound_drift_and_hardware_overclaim_fail_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["validation"] = str((ARTIFACT.parent / artifact["validation"]).resolve())
    artifact["pages"] = [0, 1, 2, 3]
    path = tmp_path / "fault.json"
    path.write_text(json.dumps(artifact))
    assert verify_fault_recovery(path)["code"] == "FAULT_RECOVERY_BOUND_INVALID"
    artifact["pages"] = [0, 1, 2]
    artifact["physical_mce_semantics_proved"] = True
    path.write_text(json.dumps(artifact))
    assert verify_fault_recovery(path)["code"] == "FAULT_RECOVERY_EPISTEMIC_BOUNDARY_INVALID"


def test_registry_forbids_physical_and_native_overclaims():
    milestone = capability("m83_fault_hardware_resilience").milestone
    assert milestone.completed_claims == ("FAULT_CONTAINMENT_RECOVERY_PROVED",)
    assert milestone.required_judges == ("TLC", "Z3", "PhysicalFaultInjection:pending")
    assert "PHYSICAL_ECC_DELIVERY_PROVED" in milestone.claims_forbidden
    assert "FAULT_HANDLER_IMPLEMENTATION_REFINEMENT_PROVED" in milestone.claims_forbidden
