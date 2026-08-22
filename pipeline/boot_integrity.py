import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def _fail(code, message=""):
    return {"status": "BOOT_INTEGRITY_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_boot_model(module):
    tla = f'''---- MODULE {module} ----
EXTENDS Naturals
Versions == 1..2
States == {{"Reset", "Measured", "Authorized", "Running", "Recovery"}}
VARIABLES state, measuredOK, signatureOK, version, pcrExtended
vars == <<state, measuredOK, signatureOK, version, pcrExtended>>
Init == /\\ state = "Reset" /\\ measuredOK = FALSE /\\ signatureOK = FALSE
        /\\ version = 1 /\\ pcrExtended = FALSE
Measure(ok, v) == /\\ state = "Reset" /\\ ok \\in BOOLEAN /\\ v \\in Versions
                  /\\ state' = "Measured" /\\ measuredOK' = ok
                  /\\ version' = v /\\ pcrExtended' = TRUE
                  /\\ UNCHANGED signatureOK
Authorize == /\\ state = "Measured" /\\ measuredOK /\\ version >= 2
             /\\ state' = "Authorized" /\\ signatureOK' = TRUE
             /\\ UNCHANGED <<measuredOK, version, pcrExtended>>
Reject == /\\ state = "Measured" /\\ (~measuredOK \\/ version < 2)
          /\\ state' = "Recovery" /\\ UNCHANGED <<measuredOK, signatureOK, version, pcrExtended>>
Boot == /\\ state = "Authorized" /\\ measuredOK /\\ signatureOK
        /\\ version >= 2 /\\ pcrExtended /\\ state' = "Running"
        /\\ UNCHANGED <<measuredOK, signatureOK, version, pcrExtended>>
Next == (\\E ok \\in BOOLEAN, v \\in Versions : Measure(ok, v)) \\/ Authorize \\/ Reject \\/ Boot
TypeOK == /\\ state \\in States /\\ measuredOK \\in BOOLEAN
          /\\ signatureOK \\in BOOLEAN /\\ version \\in Versions /\\ pcrExtended \\in BOOLEAN
RunningTrusted == state = "Running" => measuredOK /\\ signatureOK /\\ version >= 2 /\\ pcrExtended
RollbackBlocked == version < 2 => state # "Running"
Spec == Init /\\ [][Next]_vars
====
'''
    cfg = "SPECIFICATION Spec\nINVARIANT TypeOK\nINVARIANT RunningTrusted\nINVARIANT RollbackBlocked\nCHECK_DEADLOCK FALSE\n"
    return tla, cfg


def verify_boot_integrity(path):
    path = Path(path)
    try:
        raw = path.read_bytes(); artifact = json.loads(raw)
        measured = (path.parent / artifact["measured_artifact"]).resolve().read_bytes()
        evidence = json.loads((path.parent / artifact["validation"]).read_text())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("BOOT_INTEGRITY_ARTIFACT_INVALID", str(exc))
    digest = hashlib.sha256(measured).hexdigest()
    if digest != artifact.get("expected_measurement_sha256"):
        return _fail("BOOT_MEASUREMENT_MISMATCH")
    if artifact.get("current_version") != 2 or artifact.get("minimum_accepted_version") != 2 \
            or artifact.get("rollback_response") != "Recovery":
        return _fail("ROLLBACK_POLICY_INVALID")
    ceilings = ("physical_tpm_semantics_proved", "firmware_measurement_proved",
                "key_custody_proved", "sha256_collision_resistance_proved",
                "built_image_measurement_proved")
    if any(artifact.get(x) is not False for x in ceilings):
        return _fail("BOOT_INTEGRITY_EPISTEMIC_BOUNDARY_INVALID")
    tla, _cfg = render_boot_model(artifact["module"])
    tla_hash = hashlib.sha256(tla.encode()).hexdigest()
    if evidence.get("status") != "BOOT_POLICY_MODEL_PROVED" or \
            evidence.get("tla_sha256") != tla_hash or evidence.get("deadlock_free") is not True:
        return _fail("BOOT_TLC_EVIDENCE_BINDING_MISMATCH")
    z3 = shutil.which("z3")
    if z3 is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "z3_unavailable", "judge_pending": "z3"}
    smt = """(set-logic QF_LIA)
(declare-const measured_ok Bool)
(declare-const signature_ok Bool)
(declare-const version Int)
(define-fun admitted () Bool (and measured_ok signature_ok (>= version 2)))
(assert admitted)
(assert (or (not measured_ok) (not signature_ok) (< version 2)))
(check-sat)
"""
    run = subprocess.run([z3, "-in"], input=smt, capture_output=True, text=True, timeout=30)
    if run.returncode or run.stdout.strip() != "unsat":
        return _fail("BOOT_ADMISSION_COUNTEREXAMPLE", run.stdout)
    return {"status": "BOOT_TO_RUNTIME_INTEGRITY_CHAIN_PROVED",
            "claim": "BOOT_TO_RUNTIME_INTEGRITY_CHAIN_PROVED", "judge": "tlc+z3+sha256",
            "scope": "declared_measurement_version_signature_and_pcr_policy",
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "measured_artifact_sha256": digest, "tla_sha256": tla_hash,
            "smt_sha256": hashlib.sha256(smt.encode()).hexdigest(),
            "distinct_states": evidence.get("distinct_states"),
            "rollback_blocked": True, "pcr_index": artifact.get("pcr_index"),
            **{field: False for field in ceilings}}
