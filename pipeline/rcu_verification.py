# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M71 bounded RCU witness and parameterized-proof boundary."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "RCU_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_rcu_bounded(artifact_path: str | Path) -> dict:
    """Run ESBMC over the exact two-reader RCU grace-period witness."""
    path = Path(artifact_path)
    try:
        raw = path.read_bytes()
        artifact = json.loads(raw)
        source = path.parent / artifact["source"]
        proof = path.parent / artifact["parameterized_proof"]
        source_bytes = source.read_bytes()
        proof_bytes = proof.read_bytes()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("RCU_ARTIFACT_INVALID", str(exc))
    text = source_bytes.decode("utf-8", errors="strict")
    required = (artifact.get("bounded_readers") == 2,
                "#define READERS 2" in text,
                text.count("pthread_create") == 3,
                "reader_epoch[0] > callback_epoch" in text,
                "reader_epoch[1] > callback_epoch" in text)
    if not all(required):
        return _fail("RCU_WITNESS_BINDING_MISMATCH")
    if "THEOREM InvIsInductive" not in proof_bytes.decode("utf-8", errors="strict"):
        return _fail("RCU_PARAMETERIZED_PROOF_BINDING_MISMATCH")
    tlapm = shutil.which("tlapm")
    if tlapm is None:
        local_tlapm = Path.cwd() / ".tools" / "bin" / "tlapm"
        tlapm = str(local_tlapm) if local_tlapm.is_file() else None
    if tlapm is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "tlapm_unavailable", "judge_pending": "tlapm"}
    esbmc = shutil.which("esbmc")
    if esbmc is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "esbmc_unavailable", "judge_pending": "esbmc"}
    with tempfile.TemporaryDirectory(prefix="formalkernel-rcu-") as directory:
        staged_proof = Path(directory) / "RCURefinement.tla"
        staged_proof.write_bytes(proof_bytes)
        staged = Path(directory) / "rcu_witness.c"
        staged.write_bytes(source_bytes)
        try:
            tlaps_run = subprocess.run(
                [tlapm, "--cleanfp", "--nofp", staged_proof.name],
                cwd=directory, capture_output=True, text=True, timeout=300)
            run = subprocess.run([esbmc, str(staged), "--unwind", "5",
                                  "--context-bound", "3"],
                                 capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return _fail("RCU_ESBMC_EXECUTION_FAILED", str(exc))
    tlaps_output = (tlaps_run.stdout or "") + (tlaps_run.stderr or "")
    if tlaps_run.returncode != 0 or "All 10 obligations proved" not in tlaps_output:
        return _fail("RCU_PARAMETERIZED_PROOF_FAILED", tlaps_output[-500:])
    output = (run.stdout or "") + (run.stderr or "")
    if "VERIFICATION SUCCESSFUL" not in output:
        return _fail("RCU_BOUNDED_COUNTEREXAMPLE", output[-500:])
    return {
        "status": "RCU_RECLAMATION_SAFETY_PROVED",
        "claim": "RCU_RECLAMATION_SAFETY_PROVED",
        "judge": "tlapm+esbmc",
        "scope": "parameterized_grace_period_invariant",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
        "tlaps_obligations_proved": 10,
        "bounded_readers": 2, "unwind": 5, "context_bound": 3,
        "parameterized_grace_period_proved": True,
        "implementation_refinement_proved": False,
        "irq_nmi_interaction_proved": False,
        "callback_pressure_proved": False,
        "judge_pending": "rcu_source_model_refinement_irq_nmi_callback_pressure",
    }
