import json
from pathlib import Path
from pipeline.boot_integrity import verify_boot_integrity

ARTIFACT = Path("examples/formalkernel/kernel/boot_integrity.json")

def test_measured_boot_and_rollback_policy():
    verdict = verify_boot_integrity(ARTIFACT)
    assert verdict["status"] == "BOOT_TO_RUNTIME_INTEGRITY_CHAIN_PROVED"
    assert verdict["distinct_states"] == 10 and verdict["rollback_blocked"] is True
    assert verdict["physical_tpm_semantics_proved"] is False

def test_rollback_or_tpm_overclaim_fails_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text()); artifact["minimum_accepted_version"] = 1
    artifact["measured_artifact"] = str((ARTIFACT.parent / artifact["measured_artifact"]).resolve())
    artifact["validation"] = str((ARTIFACT.parent / artifact["validation"]).resolve())
    path = tmp_path / "boot.json"; path.write_text(json.dumps(artifact))
    assert verify_boot_integrity(path)["code"] == "ROLLBACK_POLICY_INVALID"
    artifact["minimum_accepted_version"] = 2; artifact["physical_tpm_semantics_proved"] = True
    path.write_text(json.dumps(artifact))
    assert verify_boot_integrity(path)["code"] == "BOOT_INTEGRITY_EPISTEMIC_BOUNDARY_INVALID"
