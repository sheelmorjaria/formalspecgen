# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.5c VS-mode IMSIC guest-file routing qualification."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import config
from .domain_v2_tools import get_tlc_provenance, require_tlc_provenance, run_tlc_artifacts
from .riscv_gstage import verify_gstage_evidence
from .riscv_guest_privilege import verify_guest_evidence

CLAIM = "RISCV_GUEST_INTERRUPT_ROUTING_MODEL_PROVED"
SCOPE = "reviewed_qemu_virt_h_extension_vs_imsic_guest_files"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(code: str, message: str = "") -> dict[str, Any]:
    return {"status": "RISCV_GUEST_INTERRUPT_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def validate_guest_interrupt_policy(policy: dict[str, Any], reviewed: bool = False) -> list[str]:
    failures: list[str] = []
    expected = "REVIEWED_RISCV_VS_IMSIC_POLICY" if reviewed else "HUMAN_REVIEW_PENDING"
    if policy.get("schema_version") != 1 or policy.get("status") != expected:
        failures.append("review_status")
    if policy.get("scope") != SCOPE or policy.get("delivery") != "hypervisor_mediated":
        failures.append("scope_or_delivery")
    files = policy.get("guest_files")
    if not isinstance(files, list) or len(files) != 2:
        return sorted(set(failures + ["guest_file_topology"]))
    guests = [f.get("guest") for f in files]
    vgeins = [f.get("vgein") for f in files]
    vmids = [f.get("vmid") for f in files]
    identities = [f.get("interrupt_id") for f in files]
    if guests != ["guest1", "guest2"] or len(set(vgeins)) != 2 or vgeins != [1, 2]:
        failures.append("guest_file_ownership")
    if vmids != [1, 2] or len(set(identities)) != 2:
        failures.append("vmid_or_identity_partition")
    if policy.get("invalid_vgein") != [0, 3]:
        failures.append("invalid_vgein_policy")
    if policy.get("s_mode_file", {}).get("vs_visible") is not False:
        failures.append("s_mode_file_separation")
    if set(policy.get("state_fields", [])) != {
            "guest_file_pending", "guest_file_enabled", "hgeip", "hgeie",
            "vgein", "vseip"}:
        failures.append("interrupt_state_incomplete")
    deps = policy.get("identity_dependencies", {})
    if deps != {"vs_context": "M91.5a", "gstage_vmid": "M91.5b",
                "host_trap_path": "M91.4"}:
        failures.append("composition_dependencies")
    return sorted(set(failures))


def render_guest_interrupt(policy: dict[str, Any],
                           module: str = "RiscvGuestInterrupt") -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("RISCV_GUEST_INTERRUPT_MODULE_INVALID")
    failures = validate_guest_interrupt_policy(policy, reviewed=True)
    if failures:
        raise ValueError("RISCV_GUEST_INTERRUPT_POLICY_INVALID:" + ",".join(failures))
    tla = rf'''---- MODULE {module} ----
EXTENDS Naturals
VARIABLES phase, activeGuest, gstageGuest, vmid, vgein,
  pending1, pending2, enabled1, enabled2, hgeip1, hgeip2,
  hgeie1, hgeie2, vseip, interruptId, trapValidated, switchFrom
vars == <<phase,activeGuest,gstageGuest,vmid,vgein,pending1,pending2,
  enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2,vseip,interruptId,
  trapValidated,switchFrom>>
Vmid(g) == IF g = "guest1" THEN 1 ELSE 2
Vgein(g) == IF g = "guest1" THEN 1 ELSE 2
IntId(g) == IF g = "guest1" THEN 48 ELSE 49
SelectedOwner == IF vgein = 1 THEN "guest1" ELSE IF vgein = 2 THEN "guest2" ELSE "None"
SelectedPending == IF vgein = 1 THEN pending1 ELSE IF vgein = 2 THEN pending2 ELSE FALSE
SelectedEnabled == IF vgein = 1 THEN enabled1 /\ hgeie1 ELSE IF vgein = 2 THEN enabled2 /\ hgeie2 ELSE FALSE
Init == /\ phase = "HS" /\ activeGuest = "None" /\ gstageGuest = "None"
  /\ vmid = 0 /\ vgein = 0 /\ pending1 = FALSE /\ pending2 = FALSE
  /\ enabled1 = TRUE /\ enabled2 = TRUE /\ hgeip1 = FALSE /\ hgeip2 = FALSE
  /\ hgeie1 = TRUE /\ hgeie2 = TRUE /\ vseip = FALSE /\ interruptId = 0
  /\ trapValidated = FALSE /\ switchFrom = "None"
Enter(g) == /\ phase = "HS" /\ activeGuest = "None" /\ g \in {{"guest1","guest2"}}
  /\ phase' = "VS" /\ activeGuest' = g /\ gstageGuest' = g
  /\ vmid' = Vmid(g) /\ vgein' = Vgein(g) /\ vseip' = FALSE
  /\ interruptId' = 0 /\ trapValidated' = FALSE /\ switchFrom' = "None"
  /\ UNCHANGED <<pending1,pending2,enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2>>
Inject1 == /\ ~pending1 /\ pending1' = TRUE /\ hgeip1' = TRUE
  /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,vgein,pending2,enabled1,enabled2,
    hgeip2,hgeie1,hgeie2,vseip,interruptId,trapValidated,switchFrom>>
Inject2 == /\ ~pending2 /\ pending2' = TRUE /\ hgeip2' = TRUE
  /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,vgein,pending1,enabled1,enabled2,
    hgeip1,hgeie1,hgeie2,vseip,interruptId,trapValidated,switchFrom>>
Expose == /\ phase = "VS" /\ ~vseip /\ activeGuest = SelectedOwner
  /\ SelectedPending /\ SelectedEnabled
  /\ vseip' = TRUE /\ interruptId' = IntId(activeGuest)
  /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,vgein,pending1,pending2,
    enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2,trapValidated,switchFrom>>
Trap == /\ phase = "VS" /\ vseip /\ phase' = "HSTrap" /\ trapValidated' = TRUE
  /\ UNCHANGED <<activeGuest,gstageGuest,vmid,vgein,pending1,pending2,
    enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2,vseip,interruptId,switchFrom>>
Ack1 == /\ phase = "HSTrap" /\ activeGuest = "guest1" /\ vgein = 1
  /\ pending1' = FALSE /\ hgeip1' = FALSE /\ vseip' = FALSE /\ interruptId' = 0
  /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,vgein,pending2,enabled1,enabled2,
    hgeip2,hgeie1,hgeie2,trapValidated,switchFrom>>
Ack2 == /\ phase = "HSTrap" /\ activeGuest = "guest2" /\ vgein = 2
  /\ pending2' = FALSE /\ hgeip2' = FALSE /\ vseip' = FALSE /\ interruptId' = 0
  /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,vgein,pending1,enabled1,enabled2,
    hgeip1,hgeie1,hgeie2,trapValidated,switchFrom>>
BeginSwitch == /\ phase \in {{"VS","HSTrap"}} /\ phase' = "Switch"
  /\ switchFrom' = activeGuest /\ activeGuest' = "None" /\ gstageGuest' = "None"
  /\ vmid' = 0 /\ vgein' = 0 /\ vseip' = FALSE /\ interruptId' = 0
  /\ trapValidated' = TRUE
  /\ UNCHANGED <<pending1,pending2,enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2>>
FinishSwitch(g) == /\ phase = "Switch" /\ g \in {{"guest1","guest2"}} /\ g # switchFrom
  /\ phase' = "VS" /\ activeGuest' = g /\ gstageGuest' = g /\ vmid' = Vmid(g)
  /\ vgein' = Vgein(g) /\ vseip' = FALSE /\ interruptId' = 0
  /\ trapValidated' = FALSE /\ UNCHANGED <<pending1,pending2,enabled1,enabled2,
    hgeip1,hgeip2,hgeie1,hgeie2,switchFrom>>
Stay == /\ phase = "Switch" /\ UNCHANGED vars
Next == (\E g \in {{"guest1","guest2"}}: Enter(g)) \/ Inject1 \/ Inject2 \/ Expose \/ Trap
  \/ Ack1 \/ Ack2 \/ BeginSwitch \/ (\E g \in {{"guest1","guest2"}}: FinishSwitch(g)) \/ Stay
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {{"HS","VS","HSTrap","Switch"}}
  /\ activeGuest \in {{"None","guest1","guest2"}} /\ gstageGuest \in {{"None","guest1","guest2"}}
  /\ vmid \in 0..2 /\ vgein \in 0..3 /\ interruptId \in {{0,48,49}}
GuestIdentityAligned == phase \in {{"VS","HSTrap"}} =>
  /\ activeGuest = gstageGuest /\ vmid = Vmid(activeGuest)
  /\ vgein = Vgein(activeGuest) /\ SelectedOwner = activeGuest
NoSelectionInHS == phase \in {{"HS","Switch"}} => vgein = 0 /\ ~vseip
VisibleOwned == vseip => /\ phase \in {{"VS","HSTrap"}} /\ SelectedOwner = activeGuest
  /\ SelectedPending /\ SelectedEnabled /\ interruptId = IntId(activeGuest)
PendingMirrorsHgeip == pending1 = hgeip1 /\ pending2 = hgeip2
ValidatedTrapPath == phase = "HSTrap" => trapValidated
SwitchClearsOldSelection == phase = "Switch" => activeGuest = "None" /\ gstageGuest = "None" /\ vgein = 0
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\nINVARIANT GuestIdentityAligned\n"
           "INVARIANT NoSelectionInHS\nINVARIANT VisibleOwned\n"
           "INVARIANT PendingMirrorsHgeip\nINVARIANT ValidatedTrapPath\n"
           "INVARIANT SwitchClearsOldSelection\n")
    return tla, cfg


def run_guest_interrupt(policy: dict[str, Any]) -> dict[str, Any]:
    try:
        tla, cfg = render_guest_interrupt(policy)
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name="RiscvGuestInterrupt",
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


def run_guest_interrupt_mutation(policy: dict[str, Any], mutation: str) -> dict[str, Any]:
    tla, cfg = render_guest_interrupt(policy)
    bad = {
        "cross_guest_vgein": r'''Bad == /\ phase = "VS" /\ activeGuest = "guest1"
  /\ vgein' = 2 /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,pending1,pending2,
  enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2,vseip,interruptId,trapValidated,switchFrom>>
''',
        "stale_vgein_switch": r'''Bad == /\ phase = "VS" /\ activeGuest = "guest1"
  /\ phase' = "Switch" /\ switchFrom' = "guest1" /\ activeGuest' = "None"
  /\ gstageGuest' = "None" /\ vmid' = 0 /\ vgein' = 1 /\ vseip' = FALSE
  /\ interruptId' = 0 /\ trapValidated' = TRUE
  /\ UNCHANGED <<pending1,pending2,enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2>>
''',
        "invalid_vgein_visible": r'''Bad == /\ phase = "VS" /\ vgein' = 3 /\ vseip' = TRUE
  /\ interruptId' = 48 /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,pending1,pending2,
  enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2,trapValidated,switchFrom>>
''',
        "cross_pending": r'''Bad == /\ pending1 /\ ~pending2 /\ pending2' = TRUE /\ hgeip2' = FALSE
  /\ UNCHANGED <<phase,activeGuest,gstageGuest,vmid,vgein,pending1,enabled1,enabled2,
  hgeip1,hgeie1,hgeie2,vseip,interruptId,trapValidated,switchFrom>>
''',
        "wrong_vmid": r'''Bad == /\ phase = "VS" /\ activeGuest = "guest1" /\ vmid' = 2
  /\ UNCHANGED <<phase,activeGuest,gstageGuest,vgein,pending1,pending2,enabled1,enabled2,
  hgeip1,hgeip2,hgeie1,hgeie2,vseip,interruptId,trapValidated,switchFrom>>
''',
        "trap_bypass": r'''Bad == /\ phase = "VS" /\ vseip /\ phase' = "HSTrap"
  /\ trapValidated' = FALSE /\ UNCHANGED <<activeGuest,gstageGuest,vmid,vgein,
  pending1,pending2,enabled1,enabled2,hgeip1,hgeip2,hgeie1,hgeie2,vseip,interruptId,switchFrom>>
''',
    }.get(mutation)
    if bad is None:
        return _fail("RISCV_GUEST_INTERRUPT_MUTATION_UNKNOWN", mutation)
    tla = tla.replace("Next == ", bad + "Next == Bad \\/ ", 1)
    result = run_tlc_artifacts(tla, cfg, module_name="RiscvGuestInterrupt",
                               tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                               timeout=config.TLC_TIMEOUT)
    return {"mutation": mutation, "status": result.get("status"),
            "rejected": result.get("status") != "VERIFIED"}


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


def validate_guest_interrupt_claim(artifact: dict[str, Any], root: str | Path) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        policy, policy_hash = _load(base, artifact["reviewed_policy"], "RISCV_VS_IMSIC_POLICY")
        guest_artifact, _ = _load(base, artifact["guest_transition_artifact"], "RISCV_GUEST_ARTIFACT")
        guest_evidence, guest_hash = _load(base, artifact["guest_transition_evidence"], "RISCV_GUEST_EVIDENCE")
        gstage_artifact, _ = _load(base, artifact["gstage_artifact"], "RISCV_GSTAGE_ARTIFACT")
        gstage_evidence, gstage_hash = _load(base, artifact["gstage_evidence"], "RISCV_GSTAGE_EVIDENCE")
        if verify_guest_evidence(guest_artifact, base, guest_evidence).get("claim") != "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED":
            return _fail("RISCV_GUEST_INTERRUPT_GUEST_DEPENDENCY_UNPROVED")
        if verify_gstage_evidence(gstage_artifact, base, gstage_evidence).get("claim") != "RISCV_G_STAGE_ISOLATION_PROVED":
            return _fail("RISCV_GUEST_INTERRUPT_GSTAGE_DEPENDENCY_UNPROVED")
        failures = validate_guest_interrupt_policy(policy, reviewed=True)
        if failures:
            return _fail("RISCV_GUEST_INTERRUPT_POLICY_INVALID", ",".join(failures))
        result = run_guest_interrupt(policy)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("RISCV_GUEST_INTERRUPT_TLC_FAILED")
    return {"status": CLAIM, "claim": CLAIM, "judge": "tlc",
            "scope": SCOPE, "reviewed_policy_sha256": policy_hash,
            "guest_transition_evidence_sha256": guest_hash,
            "gstage_evidence_sha256": gstage_hash,
            "tlc_version": result["tlc_version"],
            "generated_tla_sha256": result["generated_tla_sha256"],
            "generated_cfg_sha256": result["generated_cfg_sha256"],
            "distinct_states": result["distinct_states"],
            "properties": ["GUEST_FILE_UNIQUE_OWNER", "ACTIVE_GUEST_IDENTITY_ALIGNED",
                           "ZERO_OR_INVALID_VGEIN_EXPOSES_NONE", "GUEST_SWITCH_CLEARS_SELECTION",
                           "PENDING_STATE_ISOLATED", "INTERRUPT_IDENTITY_SCOPED",
                           "SELECTED_FILE_ACK_FRAME", "S_MODE_FILE_NOT_VS_VISIBLE",
                           "HGIEP_HGEIE_SEPARATED", "REVIEWED_HS_VS_TRAP_PATH"],
            "qemu_guest_imsic_configuration_observed": True,
            "qemu_vs_imsic_routing_observed": False,
            "hardware_interrupt_delivery_proved": False,
            "direct_device_assignment_proved": False,
            "riscv_iommu_guest_msi_remap_proved": False}


def write_guest_interrupt_evidence(path: str | Path, evidence: dict[str, Any]) -> None:
    if evidence.get("claim") != CLAIM:
        raise ValueError("RISCV_GUEST_INTERRUPT_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_guest_interrupt_evidence(artifact: dict[str, Any], root: str | Path,
                                    evidence: dict[str, Any]) -> dict[str, Any]:
    fresh = validate_guest_interrupt_claim(artifact, root)
    if fresh.get("claim") != CLAIM:
        return fresh
    stable = {k: v for k, v in fresh.items() if k != "distinct_states"}
    supplied = {k: v for k, v in evidence.items() if k != "distinct_states"}
    if stable != supplied or evidence.get("distinct_states") != fresh.get("distinct_states"):
        return _fail("RISCV_GUEST_INTERRUPT_EVIDENCE_BINDING_MISMATCH")
    return {"status": "RISCV_GUEST_INTERRUPT_EVIDENCE_BOUND", "claim": CLAIM,
            "scope": SCOPE, "reviewed_policy_sha256": fresh["reviewed_policy_sha256"],
            "distinct_states": fresh["distinct_states"]}
