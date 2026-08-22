import json
from pathlib import Path
from pipeline.process_model import verify_process_model

ARTIFACT = Path("examples/formalkernel/kernel/process_model.json")

def test_process_lifecycle_and_exec_cleanup():
    verdict = verify_process_model(ARTIFACT)
    assert verdict["status"] == "PROCESS_CONCURRENCY_MODEL_PROVED"
    assert verdict["distinct_states"] == 15
    assert verdict["exec_cleanup_proved"] is True
    assert verdict["posix_conformance_proved"] is False

def test_process_overclaim_fails_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text()); artifact["posix_conformance_proved"] = True
    artifact["validation"] = str((ARTIFACT.parent / "process_model.validation.json").resolve())
    path = tmp_path / "model.json"; path.write_text(json.dumps(artifact))
    assert verify_process_model(path)["code"] == "PROCESS_MODEL_EPISTEMIC_BOUNDARY_INVALID"
