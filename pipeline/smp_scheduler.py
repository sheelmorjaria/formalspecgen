import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def verify_smp_scheduler(path):
    path = Path(path)
    try:
        raw = path.read_bytes(); artifact = json.loads(raw)
        proof = path.parent / artifact["parameterized_proof"]
        proof_raw = proof.read_bytes(); text = proof_raw.decode()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        return {"status": "SMP_SCHEDULER_FAILED", "claim": "NO_PROOF",
                "code": "SMP_SCHEDULER_ARTIFACT_INVALID", "message": str(exc)}
    expected = ["InitImpliesInv", "InvIsInductive", "MigrationConservesRunnable"]
    if artifact.get("theorems") != expected or not all(
            f"THEOREM {name}" in text for name in expected):
        return {"status": "SMP_SCHEDULER_FAILED", "claim": "NO_PROOF",
                "code": "SMP_SCHEDULER_THEOREM_BINDING_MISMATCH"}
    false_fields = ("load_balancer_implementation_refinement_proved",
                    "irq_ipi_delivery_proved", "cpu_hotplug_proved",
                    "scheduler_liveness_proved", "m77_quota_composition_proved",
                    "m71_5_interference_bound_validated")
    if artifact.get("arbitrary_finite_cpu_and_task_sets") is not True or any(
            artifact.get(field) is not False for field in false_fields):
        return {"status": "SMP_SCHEDULER_FAILED", "claim": "NO_PROOF",
                "code": "SMP_SCHEDULER_EPISTEMIC_BOUNDARY_INVALID"}
    tlapm = shutil.which("tlapm")
    if tlapm is None:
        local = Path.cwd() / ".tools/bin/tlapm"
        tlapm = str(local) if local.is_file() else None
    if tlapm is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "tlapm_unavailable", "judge_pending": "tlapm"}
    with tempfile.TemporaryDirectory(prefix="m78-smp-") as directory:
        staged = Path(directory) / proof.name; staged.write_bytes(proof_raw)
        try:
            run = subprocess.run([tlapm, "--cleanfp", "--nofp", staged.name],
                                 cwd=directory, capture_output=True, text=True,
                                 timeout=300)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "SMP_SCHEDULER_FAILED", "claim": "NO_PROOF",
                    "code": "SMP_TLAPS_FAILED", "message": str(exc)}
    output = (run.stdout or "") + (run.stderr or "")
    if run.returncode != 0 or "All" not in output or "obligations proved" not in output:
        return {"status": "SMP_SCHEDULER_FAILED", "claim": "NO_PROOF",
                "code": "SMP_PARAMETERIZED_PROOF_FAILED", "message": output[-1000:]}
    return {"status": "SMP_SCHEDULER_INVARIANTS_PROVED",
            "claim": "SMP_SCHEDULER_INVARIANTS_PROVED", "judge": "tlapm",
            "scope": "arbitrary_finite_cpu_task_sets_owner_affinity_migration",
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "proof_sha256": hashlib.sha256(proof_raw).hexdigest(),
            "parameterized": True, "theorems": expected,
            **{field: False for field in false_fields}}
