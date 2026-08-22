import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.guest_isolation import verify_guest_isolation


ARTIFACT = Path("examples/formalkernel/kernel/guest_isolation.json")


def test_guest_lifecycle_and_resource_noninterference():
    verdict = verify_guest_isolation(ARTIFACT)
    assert verdict["status"] == "GUEST_RESOURCE_NONINTERFERENCE_PROVED"
    assert verdict["lifecycle_deadlock_free"] is True
    assert verdict["iommu_domains_distinct"] is True
    assert verdict["hardware_virtualization_semantics_proved"] is False


def test_quota_drift_and_hardware_overclaim_fail_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["validation"] = str((ARTIFACT.parent / artifact["validation"]).resolve())
    artifact["quotas"]["guest_a"]["memory_pages"] = 5
    path = tmp_path / "guests.json"
    path.write_text(json.dumps(artifact))
    assert verify_guest_isolation(path)["code"] == "GUEST_RESOURCE_POLICY_INVALID"
    artifact["quotas"]["guest_a"]["memory_pages"] = 4
    artifact["nested_page_table_enforcement_proved"] = True
    path.write_text(json.dumps(artifact))
    assert verify_guest_isolation(path)["code"] == "GUEST_ISOLATION_EPISTEMIC_BOUNDARY_INVALID"


def test_registry_keeps_hardware_and_native_claims_forbidden():
    milestone = capability("m84_virtualization_isolation_domains").milestone
    assert milestone.completed_claims == ("GUEST_RESOURCE_NONINTERFERENCE_PROVED",)
    assert "NESTED_PAGE_TABLE_ENFORCEMENT_PROVED" in milestone.claims_forbidden
    assert "HYPERVISOR_IMPLEMENTATION_REFINEMENT_PROVED" in milestone.claims_forbidden
