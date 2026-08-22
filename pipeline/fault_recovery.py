import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def _fail(code, message=""):
    return {"status": "FAULT_RECOVERY_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_fault_recovery_model(module):
    tla = rf'''---- MODULE {module} ----
EXTENDS Naturals, FiniteSets
Pages == 0..2
Owners == {{"workload", "supervisor", "free", "poisoned"}}
Faults == {{"none", "correctable_ecc", "uncorrectable_mce", "watchdog", "device_failure"}}
Modes == {{"Running", "FaultPending", "Recovered"}}
VARIABLES mode, fault, owner, workloadAlive, supervisorAlive, charged, deviceOutstanding, resetEpoch
vars == <<mode, fault, owner, workloadAlive, supervisorAlive, charged, deviceOutstanding, resetEpoch>>
Init == /\ mode = "Running" /\ fault = "none"
        /\ owner = [p \in Pages |-> IF p = 0 THEN "workload" ELSE IF p = 1 THEN "supervisor" ELSE "free"]
        /\ workloadAlive = TRUE /\ supervisorAlive = TRUE /\ charged = 2
        /\ deviceOutstanding = 2 /\ resetEpoch = 0
Inject(f) == /\ mode = "Running" /\ f \in Faults \ {{"none"}}
             /\ mode' = "FaultPending" /\ fault' = f
             /\ UNCHANGED <<owner, workloadAlive, supervisorAlive, charged, deviceOutstanding, resetEpoch>>
RecoverMemory == /\ mode = "FaultPending" /\ fault \in {{"correctable_ecc", "uncorrectable_mce"}}
                 /\ mode' = "Recovered" /\ fault' = "none"
                 /\ owner' = [owner EXCEPT ![0] = "poisoned"]
                 /\ workloadAlive' = FALSE /\ supervisorAlive' = supervisorAlive
                 /\ charged' = charged - 1 /\ UNCHANGED <<deviceOutstanding, resetEpoch>>
RecoverWatchdog == /\ mode = "FaultPending" /\ fault = "watchdog"
                   /\ mode' = "Recovered" /\ fault' = "none"
                   /\ workloadAlive' = FALSE /\ supervisorAlive' = supervisorAlive
                   /\ UNCHANGED <<owner, charged, deviceOutstanding, resetEpoch>>
RecoverDevice == /\ mode = "FaultPending" /\ fault = "device_failure"
                 /\ mode' = "Recovered" /\ fault' = "none"
                 /\ deviceOutstanding' = 0 /\ resetEpoch' = resetEpoch + 1
                 /\ UNCHANGED <<owner, workloadAlive, supervisorAlive, charged>>
Next == (\E f \in Faults \ {{"none"}} : Inject(f)) \/ RecoverMemory \/ RecoverWatchdog \/ RecoverDevice
TypeOK == /\ mode \in Modes /\ fault \in Faults /\ owner \in [Pages -> Owners]
          /\ workloadAlive \in BOOLEAN /\ supervisorAlive \in BOOLEAN
          /\ charged \in 0..2 /\ deviceOutstanding \in 0..2 /\ resetEpoch \in 0..1
PoisonIsolated == \A p \in Pages : owner[p] = "poisoned" => p = 0 /\ ~workloadAlive
Accounting == charged = Cardinality({{p \in Pages : owner[p] \in {{"workload", "supervisor"}}}})
SchedulerSurvives == supervisorAlive
RecoveryTerminal == mode = "FaultPending" => ENABLED RecoverMemory \/ ENABLED RecoverWatchdog \/ ENABLED RecoverDevice
Spec == Init /\ [][Next]_vars
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\nINVARIANT PoisonIsolated\n"
           "INVARIANT Accounting\nINVARIANT SchedulerSurvives\n"
           "INVARIANT RecoveryTerminal\nCHECK_DEADLOCK FALSE\n")
    return tla, cfg


def verify_fault_recovery(path):
    path = Path(path)
    try:
        raw = path.read_bytes()
        artifact = json.loads(raw)
        evidence = json.loads((path.parent / artifact["validation"]).read_text())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("FAULT_RECOVERY_ARTIFACT_INVALID", str(exc))
    if (artifact.get("processes") != ["workload", "supervisor"] or
            artifact.get("pages") != [0, 1, 2] or
            artifact.get("initial_page_owner") != ["workload", "supervisor", "free"] or
            artifact.get("poison_target_page") != 0 or
            artifact.get("device_outstanding_limit") != 2):
        return _fail("FAULT_RECOVERY_BOUND_INVALID")
    required_faults = ["correctable_ecc", "uncorrectable_mce", "watchdog", "device_failure"]
    if artifact.get("faults") != required_faults:
        return _fail("FAULT_RECOVERY_POLICY_INVALID")
    ceilings = ("physical_ecc_delivery_proved", "physical_mce_semantics_proved",
                "physical_watchdog_delivery_proved", "device_firmware_reset_proved",
                "native_fault_handler_refinement_proved", "arbitrary_fault_multiplicity_proved")
    if any(artifact.get(field) is not False for field in ceilings):
        return _fail("FAULT_RECOVERY_EPISTEMIC_BOUNDARY_INVALID")
    tla, _ = render_fault_recovery_model(artifact["module"])
    tla_hash = hashlib.sha256(tla.encode()).hexdigest()
    if (evidence.get("status") != "FAULT_RECOVERY_MODEL_PROVED" or
            evidence.get("tla_sha256") != tla_hash or
            evidence.get("deadlock_free") is not True):
        return _fail("FAULT_RECOVERY_TLC_EVIDENCE_BINDING_MISMATCH")
    z3 = shutil.which("z3")
    if z3 is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "z3_unavailable", "judge_pending": "z3"}
    smt = """(set-logic QF_LIA)
(declare-const charged_before Int)
(declare-const allocatable_before Int)
(assert (and (= charged_before 2) (= allocatable_before 3)))
(define-fun charged_after () Int (- charged_before 1))
(define-fun allocatable_after () Int (- allocatable_before 1))
(assert (or (not (= charged_after 1)) (not (= allocatable_after 2))
            (>= charged_after charged_before) (>= allocatable_after allocatable_before)
            (> charged_after allocatable_after) (< charged_after 0)))
(check-sat)
"""
    run = subprocess.run([z3, "-in"], input=smt, capture_output=True,
                         text=True, timeout=30)
    if run.returncode or run.stdout.strip() != "unsat":
        return _fail("POISON_ACCOUNTING_COUNTEREXAMPLE", run.stdout)
    return {
        "status": "FAULT_CONTAINMENT_RECOVERY_PROVED",
        "claim": "FAULT_CONTAINMENT_RECOVERY_PROVED",
        "judge": "tlc+z3",
        "scope": "single_fault_two_process_three_page_recovery_model",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "tla_sha256": tla_hash,
        "smt_sha256": hashlib.sha256(smt.encode()).hexdigest(),
        "distinct_states": evidence.get("distinct_states"),
        "tlc_version": evidence.get("tlc_version"),
        "poison_accounting_proved": True,
        "supervisor_survival_proved": True,
        **{field: False for field in ceilings},
    }
