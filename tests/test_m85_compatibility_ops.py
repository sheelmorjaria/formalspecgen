import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.compatibility_ops import verify_compatibility_operations


ARTIFACT = Path("examples/formalkernel/kernel/posix_compat_abi.json")


def test_abi_and_host_compiled_posix_subset_are_empirically_checked():
    verdict = verify_compatibility_operations(ARTIFACT)
    assert verdict["status"] == "COMPATIBILITY_OPERATIONS_EVIDENCE_READY"
    claims = {entry["claim"]: entry for entry in verdict["claims"]}
    assert set(claims) == {"ABI_STABILITY_CHECKED", "POSIX_CONFORMANCE_TESTED"}
    assert claims["POSIX_CONFORMANCE_TESTED"]["vectors_passed"] == 9
    assert claims["POSIX_CONFORMANCE_TESTED"]["kernel_syscall_refinement_proved"] is False


def test_abi_drift_and_conformance_overclaim_fail_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["baseline"] = str((ARTIFACT.parent / artifact["baseline"]).resolve())
    artifact["implementation"] = str((ARTIFACT.parent / artifact["implementation"]).resolve())
    artifact["calls"][0]["number"] = 999
    path = tmp_path / "abi.json"
    path.write_text(json.dumps(artifact))
    assert verify_compatibility_operations(path)["code"] == "ABI_BASELINE_DRIFT"
    artifact["calls"][0]["number"] = 200
    artifact["full_posix_conformance_proved"] = True
    path.write_text(json.dumps(artifact))
    assert verify_compatibility_operations(path)["code"] == "COMPATIBILITY_EPISTEMIC_BOUNDARY_INVALID"


def test_registry_labels_evidence_as_checked_and_tested_not_proved():
    milestone = capability("m85_compatibility_operations").milestone
    assert milestone.completed_claims == ("ABI_STABILITY_CHECKED", "POSIX_CONFORMANCE_TESTED")
    assert "FULL_POSIX_CONFORMANCE_PROVED" in milestone.claims_forbidden
    assert "ABI_STABILITY_PROVED" in milestone.claims_forbidden
