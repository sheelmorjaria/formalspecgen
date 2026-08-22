# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.5d composition of reviewed RISC-V guest execution domains."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from . import config
from .domain_v2_tools import get_tlc_provenance, require_tlc_provenance, run_tlc_artifacts
from .riscv_gstage import verify_gstage_evidence
from .riscv_guest_interrupt import verify_guest_interrupt_evidence
from .riscv_guest_privilege import verify_guest_evidence

CLAIM = "RISCV_GUEST_ISOLATION_MODEL_PROVED"
SCOPE = "reviewed_qemu_virt_hs_vs_gstage_imsic_composition"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(code: str, message: str = "") -> dict[str, Any]:
    return {"status": "RISCV_GUEST_ISOLATION_COMPOSITION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_guest_isolation_composition(
        module: str = "RiscvGuestIsolationComposition") -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("RISCV_GUEST_ISOLATION_MODULE_INVALID")
    tla = rf'''---- MODULE {module} ----
EXTENDS Naturals
VARIABLES phase, runningGuest, targetGuest, vsOwner, memoryOwner, interruptOwner,
  vmidEpoch, interruptEpoch, vsAllowed, trapValidated, memoryObserved,
  interruptObserved
vars == <<phase,runningGuest,targetGuest,vsOwner,memoryOwner,interruptOwner,
  vmidEpoch,interruptEpoch,vsAllowed,trapValidated,memoryObserved,interruptObserved>>
Other(g) == IF g = "guest1" THEN "guest2" ELSE "guest1"
Epoch(g) == IF g = "guest1" THEN 1 ELSE 2
TupleCoherent(g) == vsOwner = g /\ memoryOwner = g /\ interruptOwner = g
  /\ vmidEpoch = Epoch(g) /\ interruptEpoch = Epoch(g)
Init == /\ phase = "Running" /\ runningGuest = "guest1" /\ targetGuest = "None"
  /\ vsOwner = "guest1" /\ memoryOwner = "guest1" /\ interruptOwner = "guest1"
  /\ vmidEpoch = 1 /\ interruptEpoch = 1 /\ vsAllowed = TRUE
  /\ trapValidated = FALSE /\ memoryObserved = "None" /\ interruptObserved = "None"
ObserveMemory == /\ phase = "Running" /\ vsAllowed
  /\ memoryObserved' = memoryOwner
  /\ UNCHANGED <<phase,runningGuest,targetGuest,vsOwner,memoryOwner,interruptOwner,
    vmidEpoch,interruptEpoch,vsAllowed,trapValidated,interruptObserved>>
ObserveInterrupt == /\ phase = "Running" /\ vsAllowed
  /\ interruptObserved' = interruptOwner
  /\ UNCHANGED <<phase,runningGuest,targetGuest,vsOwner,memoryOwner,interruptOwner,
    vmidEpoch,interruptEpoch,vsAllowed,trapValidated,memoryObserved>>
TrapAndQuiesce == /\ phase = "Running" /\ vsAllowed
  /\ phase' = "Quiesced" /\ targetGuest' = Other(runningGuest) /\ vsAllowed' = FALSE
  /\ trapValidated' = TRUE /\ memoryObserved' = "None" /\ interruptObserved' = "None"
  /\ UNCHANGED <<runningGuest,vsOwner,memoryOwner,interruptOwner,vmidEpoch,interruptEpoch>>
UpdateMemory == /\ phase = "Quiesced" /\ trapValidated
  /\ phase' = "MemoryUpdated" /\ memoryOwner' = targetGuest
  /\ vmidEpoch' = Epoch(targetGuest)
  /\ UNCHANGED <<runningGuest,targetGuest,vsOwner,interruptOwner,interruptEpoch,
    vsAllowed,trapValidated,memoryObserved,interruptObserved>>
UpdateInterrupt == /\ phase = "MemoryUpdated" /\ ~vsAllowed
  /\ phase' = "InterruptUpdated" /\ interruptOwner' = targetGuest
  /\ interruptEpoch' = Epoch(targetGuest)
  /\ UNCHANGED <<runningGuest,targetGuest,vsOwner,memoryOwner,vmidEpoch,
    vsAllowed,trapValidated,memoryObserved,interruptObserved>>
ValidateTuple == /\ phase = "InterruptUpdated" /\ trapValidated
  /\ memoryOwner = targetGuest /\ interruptOwner = targetGuest
  /\ vmidEpoch = Epoch(targetGuest) /\ interruptEpoch = Epoch(targetGuest)
  /\ phase' = "Coherent" /\ vsOwner' = targetGuest
  /\ UNCHANGED <<runningGuest,targetGuest,memoryOwner,interruptOwner,vmidEpoch,
    interruptEpoch,vsAllowed,trapValidated,memoryObserved,interruptObserved>>
Resume == /\ phase = "Coherent" /\ TupleCoherent(targetGuest)
  /\ phase' = "Running" /\ runningGuest' = targetGuest /\ targetGuest' = "None"
  /\ vsAllowed' = TRUE /\ trapValidated' = FALSE
  /\ UNCHANGED <<vsOwner,memoryOwner,interruptOwner,vmidEpoch,interruptEpoch,
    memoryObserved,interruptObserved>>
Next == ObserveMemory \/ ObserveInterrupt \/ TrapAndQuiesce \/ UpdateMemory
  \/ UpdateInterrupt \/ ValidateTuple \/ Resume
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {{"Running","Quiesced","MemoryUpdated","InterruptUpdated","Coherent"}}
  /\ runningGuest \in {{"guest1","guest2"}} /\ targetGuest \in {{"None","guest1","guest2"}}
  /\ vsOwner \in {{"guest1","guest2"}} /\ memoryOwner \in {{"guest1","guest2"}}
  /\ interruptOwner \in {{"guest1","guest2"}} /\ vmidEpoch \in 1..2
  /\ interruptEpoch \in 1..2 /\ memoryObserved \in {{"None","guest1","guest2"}}
  /\ interruptObserved \in {{"None","guest1","guest2"}}
ExecutionRequiresCoherence == vsAllowed => phase = "Running" /\ TupleCoherent(runningGuest)
MismatchCannotExecute == ~TupleCoherent(runningGuest) => ~vsAllowed
SwitchIsQuiesced == phase # "Running" => ~vsAllowed /\ trapValidated
MemoryOwnership == memoryObserved # "None" => memoryObserved = runningGuest
InterruptOwnership == interruptObserved # "None" => interruptObserved = runningGuest
StaleContextRejected == phase = "Coherent" =>
  /\ TupleCoherent(targetGuest) /\ vmidEpoch = Epoch(targetGuest)
  /\ interruptEpoch = Epoch(targetGuest)
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\n"
           "INVARIANT ExecutionRequiresCoherence\nINVARIANT MismatchCannotExecute\n"
           "INVARIANT SwitchIsQuiesced\nINVARIANT MemoryOwnership\n"
           "INVARIANT InterruptOwnership\nINVARIANT StaleContextRejected\n")
    return tla, cfg


def run_guest_isolation_composition() -> dict[str, Any]:
    try:
        tla, cfg = render_guest_isolation_composition()
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name="RiscvGuestIsolationComposition",
                                   tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    states = re.search(r"(\d+) distinct states found", result.get("output", ""))
    return {"status": result.get("status"), "claim": "NO_PROOF",
            "tlc_version": provenance["version"],
            "generated_tla_sha256": _sha(tla.encode()),
            "generated_cfg_sha256": _sha(cfg.encode()),
            "distinct_states": int(states.group(1)) if states else None}


def run_composition_mutation(mutation: str) -> dict[str, Any]:
    tla, cfg = render_guest_isolation_composition()
    bad = {
        "cpu_b_memory_a": r'''Bad == /\ phase = "Running" /\ runningGuest = "guest1"
  /\ vsOwner' = "guest2" /\ UNCHANGED <<phase,runningGuest,targetGuest,memoryOwner,
  interruptOwner,vmidEpoch,interruptEpoch,vsAllowed,trapValidated,memoryObserved,interruptObserved>>
''',
        "memory_b_interrupt_a": r'''Bad == /\ phase = "Quiesced" /\ targetGuest = "guest2"
  /\ phase' = "Coherent" /\ memoryOwner' = "guest2" /\ vmidEpoch' = 2
  /\ vsOwner' = "guest2" /\ UNCHANGED <<runningGuest,targetGuest,interruptOwner,
  interruptEpoch,vsAllowed,trapValidated,memoryObserved,interruptObserved>>
''',
        "interrupt_before_quiesce": r'''Bad == /\ phase = "Running" /\ runningGuest = "guest1"
  /\ interruptOwner' = "guest2" /\ interruptEpoch' = 2
  /\ UNCHANGED <<phase,runningGuest,targetGuest,vsOwner,memoryOwner,vmidEpoch,
  vsAllowed,trapValidated,memoryObserved,interruptObserved>>
''',
        "resume_before_memory": r'''Bad == /\ phase = "Quiesced" /\ targetGuest = "guest2"
  /\ phase' = "Running" /\ runningGuest' = "guest2" /\ vsAllowed' = TRUE
  /\ UNCHANGED <<targetGuest,vsOwner,memoryOwner,interruptOwner,vmidEpoch,
  interruptEpoch,trapValidated,memoryObserved,interruptObserved>>
''',
        "stale_vmid_epoch": r'''Bad == /\ phase = "InterruptUpdated" /\ targetGuest = "guest2"
  /\ phase' = "Coherent" /\ vsOwner' = "guest2" /\ vmidEpoch' = 1
  /\ UNCHANGED <<runningGuest,targetGuest,memoryOwner,interruptOwner,interruptEpoch,
  vsAllowed,trapValidated,memoryObserved,interruptObserved>>
''',
        "stale_interrupt_visible": r'''Bad == /\ phase = "Running" /\ runningGuest = "guest2"
  /\ interruptObserved' = "guest1" /\ UNCHANGED <<phase,runningGuest,targetGuest,
  vsOwner,memoryOwner,interruptOwner,vmidEpoch,interruptEpoch,vsAllowed,
  trapValidated,memoryObserved>>
''',
        "cross_guest_memory": r'''Bad == /\ phase = "Running" /\ runningGuest = "guest2"
  /\ memoryObserved' = "guest1" /\ UNCHANGED <<phase,runningGuest,targetGuest,
  vsOwner,memoryOwner,interruptOwner,vmidEpoch,interruptEpoch,vsAllowed,
  trapValidated,interruptObserved>>
''',
        "mismatch_continues": r'''Bad == /\ phase = "MemoryUpdated" /\ vsAllowed' = TRUE
  /\ UNCHANGED <<phase,runningGuest,targetGuest,vsOwner,memoryOwner,interruptOwner,
  vmidEpoch,interruptEpoch,trapValidated,memoryObserved,interruptObserved>>
''',
        "unvalidated_switch": r'''Bad == /\ phase = "Running" /\ phase' = "Quiesced"
  /\ targetGuest' = Other(runningGuest) /\ vsAllowed' = FALSE /\ trapValidated' = FALSE
  /\ UNCHANGED <<runningGuest,vsOwner,memoryOwner,interruptOwner,vmidEpoch,
  interruptEpoch,memoryObserved,interruptObserved>>
''',
    }.get(mutation)
    if bad is None:
        return _fail("RISCV_GUEST_ISOLATION_MUTATION_UNKNOWN", mutation)
    tla = tla.replace("Next == ", bad + "Next == Bad \\/ ", 1)
    result = run_tlc_artifacts(tla, cfg, module_name="RiscvGuestIsolationComposition",
                               tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                               timeout=config.TLC_TIMEOUT)
    status = result.get("status")
    normalized = json.dumps({"mutation": mutation, "status": status},
                            sort_keys=True, separators=(",", ":")).encode()
    return {"mutation": mutation, "status": status,
            "rejected": status != "VERIFIED",
            "generated_tla_sha256": _sha(tla.encode()),
            "judge_output_sha256": _sha(normalized),
            "judge_output_normalization": "canonical_mutation_and_status"}


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


def validate_guest_isolation_composition(artifact: dict[str, Any], root: str | Path) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        ga, _ = _load(base, artifact["guest_transition_artifact"], "GUEST_TRANSITION_ARTIFACT")
        ge, geh = _load(base, artifact["guest_transition_evidence"], "GUEST_TRANSITION_EVIDENCE")
        ma, _ = _load(base, artifact["gstage_artifact"], "GSTAGE_ARTIFACT")
        me, meh = _load(base, artifact["gstage_evidence"], "GSTAGE_EVIDENCE")
        ia, _ = _load(base, artifact["guest_interrupt_artifact"], "GUEST_INTERRUPT_ARTIFACT")
        ie, ieh = _load(base, artifact["guest_interrupt_evidence"], "GUEST_INTERRUPT_EVIDENCE")
        if verify_guest_evidence(ga, base, ge).get("claim") != "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED":
            return _fail("GUEST_TRANSITION_DEPENDENCY_UNPROVED")
        if verify_gstage_evidence(ma, base, me).get("claim") != "RISCV_G_STAGE_ISOLATION_PROVED":
            return _fail("GSTAGE_DEPENDENCY_UNPROVED")
        if verify_guest_interrupt_evidence(ia, base, ie).get("claim") != "RISCV_GUEST_INTERRUPT_ROUTING_MODEL_PROVED":
            return _fail("GUEST_INTERRUPT_DEPENDENCY_UNPROVED")
        if me.get("vmidlen_assumption") != 7:
            return _fail("VMIDLEN_ASSUMPTION_MISSING")
        result = run_guest_isolation_composition()
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("COMPOSITION_TLC_FAILED")
    mutation_names = ["cpu_b_memory_a", "memory_b_interrupt_a",
                      "interrupt_before_quiesce", "resume_before_memory",
                      "stale_vmid_epoch", "stale_interrupt_visible",
                      "cross_guest_memory", "mismatch_continues",
                      "unvalidated_switch"]
    mutations = [run_composition_mutation(name) for name in mutation_names]
    if not all(item.get("rejected") for item in mutations):
        return _fail("COMPOSITION_MUTATION_SURVIVED")
    java = shutil.which(config.JAVA_BIN)
    return {"status": CLAIM, "claim": CLAIM, "judge": "tlc_composition",
            "scope": SCOPE,
            "guest_transition_evidence_sha256": geh,
            "gstage_evidence_sha256": meh,
            "guest_interrupt_evidence_sha256": ieh,
            "reviewed_transition_policy_sha256": ge["reviewed_policy_sha256"],
            "reviewed_gstage_plan_sha256": me["reviewed_plan_sha256"],
            "reviewed_interrupt_policy_sha256": ie["reviewed_policy_sha256"],
            "generated_tla_sha256": result["generated_tla_sha256"],
            "composition_model_sha256": result["generated_tla_sha256"],
            "generated_cfg_sha256": result["generated_cfg_sha256"],
            "tlc_version": result["tlc_version"], "distinct_states": result["distinct_states"],
            "judge_executable_sha256": {
                "java": _sha(Path(java).resolve().read_bytes()) if java else "unavailable",
                "tla2tools_jar": _sha(Path(config.TLC_JAR).read_bytes())},
            "mutations_executed": len(mutations),
            "mutations_rejected": sum(bool(item["rejected"]) for item in mutations),
            "mutation_results": mutations,
            "properties": ["CPU_MEMORY_IDENTITY_COHERENCE",
                           "CPU_INTERRUPT_IDENTITY_COHERENCE",
                           "MEMORY_INTERRUPT_IDENTITY_COHERENCE",
                           "QUIESCED_GUEST_SWITCH_ATOMICITY", "MISMATCH_TRAP_CONTAINMENT",
                           "GUEST_MEMORY_OWNERSHIP", "GUEST_INTERRUPT_OWNERSHIP",
                           "STALE_CONTEXT_REJECTION"],
            "vmidlen_assumption": 7,
            "qemu_h_extension_semantics_proved": False,
            "hardware_g_stage_walk_proved": False,
            "hardware_guest_interrupt_delivery_proved": False,
            "compiled_hypervisor_refinement_proved": False,
            "physical_guest_isolation_proved": False,
            "guest_device_dma_isolation_proved": False,
            "direct_device_assignment_proved": False,
            "iommu_guest_msi_remap_proved": False}


def write_guest_isolation_evidence(path: str | Path, evidence: dict[str, Any]) -> None:
    if evidence.get("claim") != CLAIM:
        raise ValueError("RISCV_GUEST_ISOLATION_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_guest_isolation_evidence(artifact: dict[str, Any], root: str | Path,
                                    evidence: dict[str, Any]) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        bindings = {
            "guest_transition_evidence_sha256": (artifact["guest_transition_evidence"], "GE"),
            "gstage_evidence_sha256": (artifact["gstage_evidence"], "ME"),
            "guest_interrupt_evidence_sha256": (artifact["guest_interrupt_evidence"], "IE")}
        hashes = {field: _load(base, binding, code)[1]
                  for field, (binding, code) in bindings.items()}
        tla, cfg = render_guest_isolation_composition()
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    valid = (evidence.get("claim") == CLAIM and evidence.get("status") == CLAIM
             and evidence.get("scope") == SCOPE and evidence.get("judge") == "tlc_composition"
             and all(evidence.get(k) == v for k, v in hashes.items())
             and evidence.get("generated_tla_sha256") == _sha(tla.encode())
             and evidence.get("composition_model_sha256") == _sha(tla.encode())
             and evidence.get("generated_cfg_sha256") == _sha(cfg.encode())
             and evidence.get("vmidlen_assumption") == 7
             and evidence.get("mutations_executed") == 9
             and evidence.get("mutations_rejected") == 9
             and all(evidence.get(k) is False for k in (
                 "qemu_h_extension_semantics_proved", "hardware_g_stage_walk_proved",
                 "hardware_guest_interrupt_delivery_proved", "compiled_hypervisor_refinement_proved",
                 "physical_guest_isolation_proved", "guest_device_dma_isolation_proved",
                 "direct_device_assignment_proved", "iommu_guest_msi_remap_proved")))
    if not valid:
        return _fail("RISCV_GUEST_ISOLATION_EVIDENCE_BINDING_MISMATCH")
    return {"status": "RISCV_GUEST_ISOLATION_EVIDENCE_BOUND", "claim": CLAIM,
            "scope": SCOPE, "distinct_states": evidence.get("distinct_states")}
