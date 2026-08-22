# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.5a HS/VS guest privilege-transition model judged by TLC."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from . import config
from .domain_v2_tools import get_tlc_provenance, require_tlc_provenance, run_tlc_artifacts

CLAIM = "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED"
SCOPE = "reviewed_qemu_virt_h_extension_hs_vs"

def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def _fail(code: str, message: str = "") -> dict[str, Any]:
    return {"status": "RISCV_GUEST_PRIVILEGE_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}

def validate_guest_policy(policy: dict[str, Any], reviewed: bool = False) -> list[str]:
    expected = "REVIEWED_RISCV_HS_VS_POLICY" if reviewed else "HUMAN_REVIEW_PENDING"
    failures = []
    if policy.get("schema_version") != 1 or policy.get("status") != expected:
        failures.append("review_status")
    if policy.get("scope") != SCOPE or policy.get("cpu_model") != "rv64":
        failures.append("scope")
    guests = policy.get("guests")
    if not isinstance(guests, list) or len(guests) != 2:
        return sorted(set(failures + ["guest_population"]))
    if {g.get("guest") for g in guests} != {"guest1", "guest2"}:
        failures.append("guest_identity")
    vmids = [g.get("vmid") for g in guests]
    contexts = [g.get("context") for g in guests]
    if any(not isinstance(v, int) or v <= 0 for v in vmids) or len(set(vmids)) != 2:
        failures.append("vmid")
    if any(not isinstance(c, str) or not c for c in contexts) or len(set(contexts)) != 2:
        failures.append("context")
    return sorted(set(failures))

def render_guest_privilege(policy: dict[str, Any],
                           module: str = "RiscvGuestPrivilege") -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("RISCV_GUEST_MODULE_INVALID")
    failures = validate_guest_policy(policy, reviewed=True)
    if failures:
        raise ValueError("RISCV_GUEST_POLICY_INVALID:" + ",".join(failures))
    tla = rf'''---- MODULE {module} ----
EXTENDS Naturals
VARIABLES mode, phase, activeGuest, requestedGuest, activeVmid,
          contextValid, dispatchValidated, hasTrapped
vars == <<mode,phase,activeGuest,requestedGuest,activeVmid,
          contextValid,dispatchValidated,hasTrapped>>
Guests == {{"guest1","guest2"}}
Vmid(g) == IF g = "guest1" THEN 1 ELSE 2
Init == /\ mode = "HS" /\ phase = "Idle" /\ activeGuest = "None"
        /\ requestedGuest = "None" /\ activeVmid = 0 /\ contextValid = FALSE
        /\ dispatchValidated = FALSE /\ hasTrapped = FALSE
PrepareGuest(g) == /\ mode = "HS" /\ phase = "Idle" /\ g \in Guests
  /\ mode' = mode /\ phase' = "Prepared" /\ activeGuest' = g
  /\ requestedGuest' = g /\ activeVmid' = Vmid(g) /\ contextValid' = TRUE
  /\ dispatchValidated' = FALSE /\ hasTrapped' = FALSE
EnterVS == /\ mode = "HS" /\ phase = "Prepared" /\ contextValid
  /\ requestedGuest = activeGuest /\ activeVmid = Vmid(activeGuest)
  /\ mode' = "VS" /\ phase' = "Running"
  /\ UNCHANGED <<activeGuest,requestedGuest,activeVmid,contextValid,
                 dispatchValidated,hasTrapped>>
GuestTrap == /\ mode = "VS" /\ phase = "Running"
  /\ requestedGuest' \in Guests /\ mode' = "HS" /\ phase' = "TrapEntry"
  /\ dispatchValidated' = FALSE /\ hasTrapped' = TRUE
  /\ UNCHANGED <<activeGuest,activeVmid,contextValid>>
ValidateDispatch == /\ mode = "HS" /\ phase = "TrapEntry"
  /\ requestedGuest = activeGuest /\ activeVmid = Vmid(activeGuest)
  /\ mode' = mode /\ phase' = "DispatchChecked" /\ dispatchValidated' = TRUE
  /\ UNCHANGED <<activeGuest,requestedGuest,activeVmid,contextValid,hasTrapped>>
RejectCrossGuest == /\ mode = "HS" /\ phase = "TrapEntry"
  /\ requestedGuest # activeGuest /\ mode' = mode /\ phase' = "Rejected"
  /\ UNCHANGED <<activeGuest,requestedGuest,activeVmid,contextValid,
                 dispatchValidated,hasTrapped>>
ResumeVS == /\ mode = "HS" /\ phase = "DispatchChecked" /\ dispatchValidated
  /\ requestedGuest = activeGuest /\ activeVmid = Vmid(activeGuest) /\ contextValid
  /\ mode' = "VS" /\ phase' = "Running"
  /\ UNCHANGED <<activeGuest,requestedGuest,activeVmid,contextValid,
                 dispatchValidated,hasTrapped>>
RemainRejected == /\ mode = "HS" /\ phase = "Rejected" /\ UNCHANGED vars
Next == (\E g \in Guests: PrepareGuest(g)) \/ EnterVS \/ GuestTrap
        \/ ValidateDispatch \/ RejectCrossGuest \/ ResumeVS \/ RemainRejected
Spec == Init /\ [][Next]_vars
TypeOK == /\ mode \in {{"HS","VS"}}
  /\ phase \in {{"Idle","Prepared","Running","TrapEntry","DispatchChecked","Rejected"}}
  /\ activeGuest \in Guests \cup {{"None"}} /\ requestedGuest \in Guests \cup {{"None"}}
  /\ activeVmid \in 0..2
VSRequiresReviewedContext == mode = "VS" =>
  /\ phase = "Running" /\ contextValid /\ activeGuest \in Guests
  /\ requestedGuest = activeGuest /\ activeVmid = Vmid(activeGuest)
TrappedResumeRequiresDispatch == mode = "VS" /\ hasTrapped => dispatchValidated
CrossGuestSelectionRejected == requestedGuest \in Guests
  /\ activeGuest \in Guests /\ requestedGuest # activeGuest => mode = "HS"
HSDispatchPathRequired == phase = "DispatchChecked" => mode = "HS" /\ dispatchValidated
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\n"
           "INVARIANT VSRequiresReviewedContext\n"
           "INVARIANT TrappedResumeRequiresDispatch\n"
           "INVARIANT CrossGuestSelectionRejected\n"
           "INVARIANT HSDispatchPathRequired\n")
    return tla, cfg

def run_guest_model(policy: dict[str, Any],
                    module: str = "RiscvGuestPrivilege") -> dict[str, Any]:
    try:
        tla, cfg = render_guest_privilege(policy, module)
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=module,
                                   tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    output = result.get("output", "")
    states = re.search(r"(\d+) distinct states found", output)
    return {"status": result.get("status"), "claim": "NO_PROOF",
            "tlc_version": provenance["version"],
            "generated_tla_sha256": _sha(tla.encode()),
            "generated_cfg_sha256": _sha(cfg.encode()),
            "distinct_states": int(states.group(1)) if states else None,
            "output": output}

def run_guest_mutation(policy: dict[str, Any], mutation: str) -> dict[str, Any]:
    tla, cfg = render_guest_privilege(policy)
    bad = {
        "unprepared_vs_entry": r'''Bad == /\ mode = "HS" /\ phase = "Idle"
  /\ mode' = "VS" /\ phase' = "Running" /\ activeGuest' = "guest1"
  /\ requestedGuest' = "guest1" /\ activeVmid' = 1 /\ contextValid' = FALSE
  /\ dispatchValidated' = FALSE /\ hasTrapped' = FALSE
''',
        "cross_guest_resume": r'''Bad == /\ mode = "VS" /\ phase = "Running"
  /\ mode' = "VS" /\ phase' = phase /\ requestedGuest' = "guest2"
  /\ UNCHANGED <<activeGuest,activeVmid,contextValid,dispatchValidated,hasTrapped>>
''',
        "resume_without_dispatch": r'''Bad == /\ mode = "HS" /\ phase = "TrapEntry"
  /\ requestedGuest = activeGuest /\ mode' = "VS" /\ phase' = "Running"
  /\ dispatchValidated' = FALSE
  /\ UNCHANGED <<activeGuest,requestedGuest,activeVmid,contextValid,hasTrapped>>
''',
        "wrong_vmid": r'''Bad == /\ mode = "HS" /\ phase = "Prepared"
  /\ activeGuest = "guest1" /\ mode' = "VS" /\ phase' = "Running"
  /\ activeVmid' = 2
  /\ UNCHANGED <<activeGuest,requestedGuest,contextValid,dispatchValidated,hasTrapped>>
''',
    }.get(mutation)
    if bad is None:
        return _fail("RISCV_GUEST_MUTATION_UNKNOWN", mutation)
    tla = tla.replace("Next == ", bad + "Next == Bad \\/ ", 1)
    result = run_tlc_artifacts(tla, cfg, module_name="RiscvGuestPrivilege",
                               tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                               timeout=config.TLC_TIMEOUT)
    return {"mutation": mutation, "status": result.get("status"),
            "rejected": result.get("status") != "VERIFIED",
            "output_tail": result.get("output", "")[-400:]}

def _load(root: Path, binding: Any, code: str) -> tuple[dict, str]:
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
        raise ValueError(f"{code}_BINDING_INVALID")
    path = (root / binding["path"]).resolve()
    if root not in path.parents or not path.is_file():
        raise ValueError(f"{code}_PATH_INVALID")
    digest = _sha(path.read_bytes())
    if digest != binding["sha256"]:
        raise ValueError(f"{code}_HASH_MISMATCH")
    return json.loads(path.read_text(encoding="utf-8")), digest

def validate_guest_transition(artifact: dict[str, Any], root: str | Path) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        policy, policy_hash = _load(base, artifact["reviewed_policy"], "RISCV_GUEST_POLICY")
        profile, profile_hash = _load(base, artifact["reviewed_profile"], "RISCV_PROFILE")
        feasibility, feasibility_hash = _load(base, artifact["feasibility"], "RISCV_FEASIBILITY")
        _, transition_hash = _load(base, artifact["host_transition_evidence"],
                                   "RISCV_HOST_TRANSITION")
        if profile.get("status") != "REVIEWED_RISCV_PLATFORM_PROFILE":
            return _fail("RISCV_GUEST_PROFILE_UNREVIEWED")
        h_status = feasibility.get("emulator", {}).get("machine_probe", {}).get("h_extension")
        if h_status != "AVAILABLE_IN_RV64_CPU_MODEL":
            return _fail("RISCV_GUEST_H_EXTENSION_UNAVAILABLE")
        result = run_guest_model(policy, artifact["module"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("RISCV_GUEST_TLC_FAILED", result.get("output", ""))
    return {"status": "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED",
            "claim": CLAIM, "judge": "tlc", "scope": SCOPE,
            "reviewed_policy_sha256": policy_hash,
            "reviewed_profile_sha256": profile_hash,
            "feasibility_sha256": feasibility_hash,
            "host_transition_evidence_sha256": transition_hash,
            "generated_tla_sha256": result["generated_tla_sha256"],
            "generated_cfg_sha256": result["generated_cfg_sha256"],
            "tlc_version": result["tlc_version"],
            "distinct_states": result["distinct_states"],
            "properties": ["REVIEWED_GUEST_CONTEXT_REQUIRED",
                           "CROSS_GUEST_SELECTION_REJECTED",
                           "HS_DISPATCH_PATH_REQUIRED",
                           "TRAPPED_RESUME_REQUIRES_DISPATCH",
                           "VMID_CONTEXT_CONSISTENCY"],
            "qemu_h_extension_semantics_proved": False,
            "compiled_guest_vector_refinement_proved": False,
            "physical_guest_execution_proved": False,
            "g_stage_isolation_proved": False,
            "vs_interrupt_routing_proved": False}

def write_guest_evidence(path: str | Path, evidence: dict[str, Any]) -> None:
    if evidence.get("claim") != CLAIM:
        raise ValueError("RISCV_GUEST_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")

def verify_guest_evidence(artifact: dict[str, Any], root: str | Path,
                          evidence: dict[str, Any]) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        policy, policy_hash = _load(base, artifact["reviewed_policy"], "RISCV_GUEST_POLICY")
        _, profile_hash = _load(base, artifact["reviewed_profile"], "RISCV_PROFILE")
        _, feasibility_hash = _load(base, artifact["feasibility"], "RISCV_FEASIBILITY")
        _, transition_hash = _load(base, artifact["host_transition_evidence"],
                                   "RISCV_HOST_TRANSITION")
        if validate_guest_policy(policy, reviewed=True):
            return _fail("RISCV_GUEST_REVIEWED_POLICY_INVALID")
        if policy.get("accepted_candidate_sha256") != \
                "d70b227ff084ba8ef0f59c91dc9567857a1f75ac8df8d458ab8a7957fe95b643":
            return _fail("RISCV_GUEST_ACCEPTED_CANDIDATE_MISMATCH")
        tla, cfg = render_guest_privilege(policy, artifact["module"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    properties = {"REVIEWED_GUEST_CONTEXT_REQUIRED", "CROSS_GUEST_SELECTION_REJECTED",
                  "HS_DISPATCH_PATH_REQUIRED", "TRAPPED_RESUME_REQUIRES_DISPATCH",
                  "VMID_CONTEXT_CONSISTENCY"}
    valid = (
        evidence.get("status") == "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED"
        and evidence.get("claim") == CLAIM and evidence.get("judge") == "tlc"
        and evidence.get("scope") == SCOPE
        and evidence.get("reviewed_policy_sha256") == policy_hash
        and evidence.get("reviewed_profile_sha256") == profile_hash
        and evidence.get("feasibility_sha256") == feasibility_hash
        and evidence.get("host_transition_evidence_sha256") == transition_hash
        and evidence.get("generated_tla_sha256") == _sha(tla.encode())
        and evidence.get("generated_cfg_sha256") == _sha(cfg.encode())
        and set(evidence.get("properties", [])) == properties
        and all(evidence.get(key) is False for key in (
            "qemu_h_extension_semantics_proved", "compiled_guest_vector_refinement_proved",
            "physical_guest_execution_proved", "g_stage_isolation_proved",
            "vs_interrupt_routing_proved")))
    if not valid:
        return _fail("RISCV_GUEST_EVIDENCE_BINDING_MISMATCH")
    return {"status": "RISCV_GUEST_PRIVILEGE_EVIDENCE_BOUND", "claim": CLAIM,
            "scope": SCOPE, "reviewed_policy_sha256": policy_hash,
            "distinct_states": evidence.get("distinct_states")}
