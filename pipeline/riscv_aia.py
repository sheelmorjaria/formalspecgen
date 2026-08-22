# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.4 reviewed APLIC-to-S-mode-IMSIC routing model."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import config
from .domain_v2_tools import get_tlc_provenance, require_tlc_provenance, run_tlc_artifacts
from .riscv_privilege_transition import verify_riscv_privilege_evidence

CLAIM = "RISCV_INTERRUPT_ROUTING_MODEL_PROVED"
SCOPE = "reviewed_qemu_virt_aia_aplic_imsic_smode"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(code: str, message: str = "") -> dict[str, Any]:
    return {"status": "RISCV_AIA_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


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


def validate_aia_policy(policy: dict[str, Any], reviewed: bool = False) -> list[str]:
    failures = []
    expected = "REVIEWED_RISCV_AIA_ROUTING_POLICY" if reviewed else "HUMAN_REVIEW_PENDING"
    if policy.get("schema_version") != 1 or policy.get("status") != expected:
        failures.append("review_status")
    if policy.get("scope") != SCOPE or policy.get("qemu_machine") != \
            "virt,aia=aplic-imsic,aia-guests=0":
        failures.append("scope")
    harts, files, grants = policy.get("harts"), policy.get("imsic_s_files"), policy.get("grants")
    if harts != [0, 1] or not isinstance(files, list) or not isinstance(grants, list):
        return sorted(set(failures + ["topology"]))
    file_map = {item.get("hart"): item for item in files}
    if set(file_map) != set(harts) or any(item.get("privilege") != "S" for item in files):
        failures.append("s_mode_files")
    if {g.get("source") for g in grants} != {"uart", "virtio_blk", "debug"}:
        failures.append("sources")
    for epoch in ("initial", "reconfigured"):
        used = set()
        for grant in grants:
            route = grant.get(epoch, {})
            hart, identity = route.get("hart"), route.get("interrupt_id")
            if hart not in harts or not isinstance(identity, int) or not 1 <= identity <= 255:
                failures.append(f"route:{epoch}")
                continue
            if file_map.get(hart, {}).get("address") != route.get("imsic_address"):
                failures.append(f"imsic_address:{epoch}")
            if grant.get("enabled") and (hart, identity) in used:
                failures.append(f"duplicate_identity:{epoch}")
            if grant.get("enabled"):
                used.add((hart, identity))
    debug = next((g for g in grants if g.get("source") == "debug"), {})
    if debug.get("enabled") is not False:
        failures.append("disabled_source")
    return sorted(set(failures))


def render_aia_model(policy: dict[str, Any],
                     module: str = "RiscvAiaRouting") -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("RISCV_AIA_MODULE_INVALID")
    failures = validate_aia_policy(policy, reviewed=True)
    if failures:
        raise ValueError("RISCV_AIA_POLICY_INVALID:" + ",".join(failures))
    grants = {g["source"]: g for g in policy["grants"]}
    u = grants["uart"]["initial"]
    b0, b1 = grants["virtio_blk"]["initial"], grants["virtio_blk"]["reconfigured"]
    tla = rf'''---- MODULE {module} ----
EXTENDS Naturals
VARIABLES phase, active, epoch, targetHart, interruptId, fileAddr,
          pending, dispatchValidated, trapValidated
vars == <<phase,active,epoch,targetHart,interruptId,fileAddr,
          pending,dispatchValidated,trapValidated>>
UartHart(e) == {u["hart"]}
UartId(e) == {u["interrupt_id"]}
UartFile(e) == {u["imsic_address"]}
BlkHart(e) == IF e = "Initial" THEN {b0["hart"]} ELSE {b1["hart"]}
BlkId(e) == IF e = "Initial" THEN {b0["interrupt_id"]} ELSE {b1["interrupt_id"]}
BlkFile(e) == IF e = "Initial" THEN {b0["imsic_address"]} ELSE {b1["imsic_address"]}
ExpectedHart(s,e) == IF s = "uart" THEN UartHart(e) ELSE BlkHart(e)
ExpectedId(s,e) == IF s = "uart" THEN UartId(e) ELSE BlkId(e)
ExpectedFile(s,e) == IF s = "uart" THEN UartFile(e) ELSE BlkFile(e)
DeclaredRoute == active \in {{"uart","virtio_blk"}}
  /\ targetHart = ExpectedHart(active,epoch)
  /\ interruptId = ExpectedId(active,epoch)
  /\ fileAddr = ExpectedFile(active,epoch)
Init == /\ phase = "Idle" /\ active = "None" /\ epoch = "Initial"
        /\ targetHart = 0 /\ interruptId = 0 /\ fileAddr = 0
        /\ pending = FALSE /\ dispatchValidated = FALSE /\ trapValidated = FALSE
StartUart == /\ phase = "Idle" /\ active' = "uart" /\ phase' = "Source"
             /\ UNCHANGED <<epoch,targetHart,interruptId,fileAddr,pending,dispatchValidated,trapValidated>>
StartBlk == /\ phase = "Idle" /\ active' = "virtio_blk" /\ phase' = "Source"
            /\ UNCHANGED <<epoch,targetHart,interruptId,fileAddr,pending,dispatchValidated,trapValidated>>
AplicRoute == /\ phase = "Source"
              /\ targetHart' = ExpectedHart(active,epoch)
              /\ interruptId' = ExpectedId(active,epoch)
              /\ fileAddr' = ExpectedFile(active,epoch)
              /\ phase' = "APLIC"
              /\ UNCHANGED <<active,epoch,pending,dispatchValidated,trapValidated>>
ImsicRecord == /\ phase = "APLIC" /\ DeclaredRoute
               /\ phase' = "IMSIC" /\ pending' = TRUE
               /\ UNCHANGED <<active,epoch,targetHart,interruptId,fileAddr,dispatchValidated,trapValidated>>
SupervisorTrap == /\ phase = "IMSIC" /\ pending /\ DeclaredRoute
                  /\ phase' = "TrapEntry" /\ trapValidated' = TRUE
                  /\ UNCHANGED <<active,epoch,targetHart,interruptId,fileAddr,pending,dispatchValidated>>
ValidateHandler == /\ phase = "TrapEntry" /\ trapValidated /\ DeclaredRoute
                   /\ phase' = "Dispatch" /\ dispatchValidated' = TRUE
                   /\ UNCHANGED <<active,epoch,targetHart,interruptId,fileAddr,pending,trapValidated>>
Acknowledge == /\ phase = "Dispatch" /\ dispatchValidated
               /\ phase' = "Idle" /\ active' = "None" /\ pending' = FALSE
               /\ dispatchValidated' = FALSE /\ trapValidated' = FALSE
               /\ UNCHANGED <<epoch,targetHart,interruptId,fileAddr>>
Reconfigure == /\ phase = "Idle" /\ epoch = "Initial" /\ epoch' = "Reconfigured"
               /\ UNCHANGED <<phase,active,targetHart,interruptId,fileAddr,pending,dispatchValidated,trapValidated>>
Next == StartUart \/ StartBlk \/ AplicRoute \/ ImsicRecord \/ SupervisorTrap
        \/ ValidateHandler \/ Acknowledge \/ Reconfigure
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {{"Idle","Source","APLIC","IMSIC","TrapEntry","Dispatch"}}
          /\ active \in {{"None","uart","virtio_blk"}}
          /\ epoch \in {{"Initial","Reconfigured"}}
          /\ targetHart \in {{0,1}} /\ interruptId \in 0..255
AuthorizedDelivery == phase \in {{"APLIC","IMSIC","TrapEntry","Dispatch"}} => DeclaredRoute
PendingOnlyInTargetFile == pending => phase \in {{"IMSIC","TrapEntry","Dispatch"}} /\ DeclaredRoute
DispatchRequiresDeclaredIdentity == phase = "Dispatch" => dispatchValidated /\ DeclaredRoute
TrapUsesValidatedM91Path == phase \in {{"TrapEntry","Dispatch"}} => trapValidated
DisabledSourceNeverActive == active # "debug"
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\nINVARIANT AuthorizedDelivery\n"
           "INVARIANT PendingOnlyInTargetFile\nINVARIANT DispatchRequiresDeclaredIdentity\n"
           "INVARIANT TrapUsesValidatedM91Path\nINVARIANT DisabledSourceNeverActive\n")
    return tla, cfg


def validate_aia_routing(artifact: dict[str, Any], root: str | Path) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        policy, policy_hash = _load(base, artifact["reviewed_policy"], "RISCV_AIA_POLICY")
        profile, profile_hash = _load(base, artifact["reviewed_profile"], "RISCV_PROFILE")
        trans_artifact, _ = _load(base, artifact["transition_artifact"], "RISCV_TRANSITION_ARTIFACT")
        trans_evidence, trans_hash = _load(base, artifact["transition_evidence"], "RISCV_TRANSITION_EVIDENCE")
        if verify_riscv_privilege_evidence(trans_artifact, base, trans_evidence).get("claim") != \
                "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED":
            return _fail("RISCV_AIA_TRANSITION_DEPENDENCY_UNPROVED")
        if profile.get("status") != "REVIEWED_RISCV_PLATFORM_PROFILE":
            return _fail("RISCV_AIA_PROFILE_UNREVIEWED")
        tla, cfg = render_aia_model(policy, artifact["module"])
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=artifact["module"],
                                   tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError,
            json.JSONDecodeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("RISCV_AIA_TLC_FAILED", result.get("output", ""))
    output = result.get("output", "")
    states = re.search(r"(\d+) distinct states found", output)
    return {
        "status": "RISCV_INTERRUPT_ROUTING_MODEL_PROVED", "claim": CLAIM,
        "judge": "tlc", "scope": SCOPE, "reviewed_policy_sha256": policy_hash,
        "reviewed_profile_sha256": profile_hash, "transition_evidence_sha256": trans_hash,
        "generated_tla_sha256": _sha(tla.encode()), "generated_cfg_sha256": _sha(cfg.encode()),
        "tlc_output_sha256": _sha(output.encode()), "tlc_version": provenance["version"],
        "distinct_states": int(states.group(1)) if states else None,
        "properties": ["AUTHORIZED_DELIVERY", "DISABLED_SOURCE_BLOCKED",
                       "IMSIC_TARGET_FILE_EXACT", "DECLARED_IDENTITY_DISPATCH",
                       "STALE_ROUTE_REJECTED", "M91_TRAP_PATH_REQUIRED",
                       "ACKNOWLEDGEMENT_NO_FABRICATION"],
        "hardware_interrupt_delivery_proved": False,
        "aia_implementation_refinement_proved": False,
        "physical_interrupt_routing_proved": False,
        "interrupt_latency_bound_proved": False,
    }


def qualify_aia_candidate(policy: dict[str, Any]) -> dict[str, Any]:
    """Run the candidate and hostile behavioral mutations without minting a claim."""
    failures = validate_aia_policy(policy, reviewed=False)
    if failures:
        return _fail("RISCV_AIA_CANDIDATE_INVALID", ",".join(failures))
    reviewed = json.loads(json.dumps(policy))
    reviewed["status"] = "REVIEWED_RISCV_AIA_ROUTING_POLICY"
    try:
        tla, cfg = render_aia_model(reviewed)
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
    except (ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    base = run_tlc_artifacts(tla, cfg, module_name="RiscvAiaRouting",
                             tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                             timeout=config.TLC_TIMEOUT)
    mutations = {
        "wrong_hart": ("targetHart' = ExpectedHart(active,epoch)",
                       "targetHart' = 1 - ExpectedHart(active,epoch)"),
        "wrong_interrupt_id": ("interruptId' = ExpectedId(active,epoch)",
                               "interruptId' = ExpectedId(active,epoch) + 1"),
        "wrong_imsic_file": ("fileAddr' = ExpectedFile(active,epoch)",
                             "fileAddr' = ExpectedFile(active,epoch) + 4096"),
        "trap_bypass": ('phase\' = "TrapEntry" /\\ trapValidated\' = TRUE',
                        'phase\' = "Dispatch" /\\ trapValidated\' = FALSE'),
        "ack_fabricates_pending": ('pending\' = FALSE', 'pending\' = TRUE'),
    }
    results = {}
    for name, (old, new) in mutations.items():
        mutated = tla.replace(old, new, 1)
        if mutated == tla:
            return _fail("RISCV_AIA_MUTATION_NOT_APPLIED", name)
        verdict = run_tlc_artifacts(mutated, cfg, module_name="RiscvAiaRouting",
                                    tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                                    timeout=config.TLC_TIMEOUT)
        results[name] = verdict.get("status")
    passed = base.get("status") == "VERIFIED" and all(
        value != "VERIFIED" for value in results.values())
    return {"status": "RISCV_AIA_CANDIDATE_QUALIFIED" if passed else
            "RISCV_AIA_CANDIDATE_QUALIFICATION_FAILED",
            "claim": "NO_PROOF", "tlc_version": provenance["version"],
            "base_status": base.get("status"), "mutation_results": results,
            "semantic_mutations_rejected": sum(v != "VERIFIED" for v in results.values()),
            "candidate_policy_sha256": _sha(
                (json.dumps(policy, indent=2) + "\n").encode())}


def write_aia_evidence(path: str | Path, evidence: dict[str, Any]) -> None:
    if evidence.get("claim") != CLAIM:
        raise ValueError("RISCV_AIA_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def verify_aia_evidence(artifact: dict[str, Any], root: str | Path,
                        evidence: dict[str, Any]) -> dict[str, Any]:
    """Rebind published evidence without silently rerunning or reinterpreting TLC."""
    base = Path(root).resolve()
    try:
        policy, policy_hash = _load(base, artifact["reviewed_policy"], "RISCV_AIA_POLICY")
        _, profile_hash = _load(base, artifact["reviewed_profile"], "RISCV_PROFILE")
        trans_artifact, _ = _load(base, artifact["transition_artifact"],
                                  "RISCV_TRANSITION_ARTIFACT")
        trans_evidence, trans_hash = _load(base, artifact["transition_evidence"],
                                          "RISCV_TRANSITION_EVIDENCE")
        if validate_aia_policy(policy, reviewed=True):
            return _fail("RISCV_AIA_REVIEWED_POLICY_INVALID")
        if policy.get("accepted_candidate_sha256") != \
                "840e178cf825013b5600326a1a2defd98d7c5e201e1d38f16b87fea0c7f79576":
            return _fail("RISCV_AIA_ACCEPTED_CANDIDATE_MISMATCH")
        if verify_riscv_privilege_evidence(
                trans_artifact, base, trans_evidence).get("claim") != \
                "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED":
            return _fail("RISCV_AIA_TRANSITION_DEPENDENCY_UNPROVED")
        tla, cfg = render_aia_model(policy, artifact["module"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    expected_properties = {
        "AUTHORIZED_DELIVERY", "DISABLED_SOURCE_BLOCKED", "IMSIC_TARGET_FILE_EXACT",
        "DECLARED_IDENTITY_DISPATCH", "STALE_ROUTE_REJECTED",
        "M91_TRAP_PATH_REQUIRED", "ACKNOWLEDGEMENT_NO_FABRICATION"}
    valid = (
        evidence.get("status") == "RISCV_INTERRUPT_ROUTING_MODEL_PROVED"
        and evidence.get("claim") == CLAIM and evidence.get("judge") == "tlc"
        and evidence.get("scope") == SCOPE
        and evidence.get("reviewed_policy_sha256") == policy_hash
        and evidence.get("reviewed_profile_sha256") == profile_hash
        and evidence.get("transition_evidence_sha256") == trans_hash
        and evidence.get("generated_tla_sha256") == _sha(tla.encode())
        and evidence.get("generated_cfg_sha256") == _sha(cfg.encode())
        and set(evidence.get("properties", [])) == expected_properties
        and all(evidence.get(name) is False for name in (
            "hardware_interrupt_delivery_proved",
            "aia_implementation_refinement_proved",
            "physical_interrupt_routing_proved",
            "interrupt_latency_bound_proved")))
    if not valid:
        return _fail("RISCV_AIA_EVIDENCE_BINDING_MISMATCH")
    return {"status": "RISCV_AIA_EVIDENCE_BOUND", "claim": CLAIM, "scope": SCOPE,
            "reviewed_policy_sha256": policy_hash,
            "transition_evidence_sha256": trans_hash,
            "distinct_states": evidence.get("distinct_states")}
