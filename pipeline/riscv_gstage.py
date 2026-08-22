# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.5b Sv39x4 ownership and HFENCE.GVMA lifecycle qualification."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from . import config
from .domain_v2_tools import get_tlc_provenance, require_tlc_provenance, run_tlc_artifacts
from .riscv_guest_privilege import verify_guest_evidence

CLAIM = "RISCV_G_STAGE_ISOLATION_PROVED"
SCOPE = "reviewed_qemu_virt_sv39x4_guest_translation"

def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
def _fail(code: str, message: str = "") -> dict[str, Any]:
    return {"status": "RISCV_G_STAGE_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}
def _inside(value: int, spans: list[dict]) -> bool:
    return any(int(s["start"]) <= value < int(s["end"]) for s in spans)
def _overlap(a: dict, b: dict) -> bool:
    return int(a["start"]) < int(b["end"]) and int(b["start"]) < int(a["end"])

def validate_gstage_plan(plan: dict[str, Any], reviewed: bool = False) -> list[str]:
    failures = []
    expected = "REVIEWED_RISCV_G_STAGE_PLAN" if reviewed else "HUMAN_REVIEW_PENDING"
    if plan.get("schema_version") != 1 or plan.get("status") != expected:
        failures.append("review_status")
    if plan.get("scope") != SCOPE or plan.get("mode") != "Sv39x4":
        failures.append("mode_or_scope")
    if plan.get("root_alignment") != 16384:
        failures.append("root_alignment_policy")
    vmidlen = plan.get("vmidlen_assumption")
    if not isinstance(vmidlen, int) or not 1 <= vmidlen <= 14:
        failures.append("vmidlen_assumption")
    guests = plan.get("guests")
    hs = plan.get("hs_protected")
    if not isinstance(guests, list) or len(guests) != 2 or not isinstance(hs, list):
        return sorted(set(failures + ["topology"]))
    vmids = [g.get("vmid") for g in guests]
    if len(set(vmids)) != 2 or any(not isinstance(v, int) or v >= 1 << vmidlen for v in vmids):
        failures.append("active_vmid_separation")
    for left in guests:
        root = left.get("hgatp_root")
        if not isinstance(root, int) or root % 16384:
            failures.append(f"root_alignment:{left.get('guest')}")
        if not _inside(root, hs):
            failures.append(f"root_not_hs_protected:{left.get('guest')}")
        for right in guests:
            if left is not right and any(_overlap(a, b) for a in left["owned_spa"]
                                         for b in right["owned_spa"]):
                failures.append("guest_spa_overlap")
        if any(_overlap(a, b) for a in left["owned_spa"] for b in hs):
            failures.append(f"guest_hs_overlap:{left.get('guest')}")
        for mapping in left.get("mappings", []):
            gpa, spa, perms = mapping.get("gpa"), mapping.get("spa"), mapping.get("permissions")
            if not isinstance(gpa, int) or not 0 <= gpa < 1 << 41 or gpa % 4096:
                failures.append(f"gpa:{left.get('guest')}")
            if not isinstance(spa, int) or not _inside(spa, left["owned_spa"]):
                failures.append(f"ownership:{left.get('guest')}")
            if perms not in {"RX", "RW", "R"} or perms == "RWX":
                failures.append(f"permissions:{left.get('guest')}")
        if any(not _inside(int(page), left["owned_spa"])
               for page in left.get("vs_page_table_spa", [])):
            failures.append(f"vs_walk_page_ownership:{left.get('guest')}")
    if set(plan.get("lifecycle", {}).get("require_hfence_gvma_after", [])) != {
            "page_table_modification", "vmid_reuse", "mode_change", "root_change"}:
        failures.append("hfence_policy")
    return sorted(set(failures))

def render_gstage_lifecycle(plan: dict[str, Any],
                            module: str = "RiscvGStageLifecycle") -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("RISCV_G_STAGE_MODULE_INVALID")
    failures = validate_gstage_plan(plan, reviewed=True)
    if failures:
        raise ValueError("RISCV_G_STAGE_PLAN_INVALID:" + ",".join(failures))
    tla = rf'''---- MODULE {module} ----
EXTENDS Naturals
VARIABLES phase, guest, vmid, root, mode, epoch, fencedEpoch, translationUsed
vars == <<phase,guest,vmid,root,mode,epoch,fencedEpoch,translationUsed>>
Root(g) == IF g = "guest1" THEN "Root1" ELSE "Root2"
Vmid(g) == IF g = "guest1" THEN 1 ELSE 2
Init == /\ phase = "Idle" /\ guest = "None" /\ vmid = 0 /\ root = "None"
        /\ mode = "Bare" /\ epoch = 0 /\ fencedEpoch = 0 /\ translationUsed = FALSE
Configure(g) == /\ phase = "Idle" /\ g \in {{"guest1","guest2"}}
  /\ epoch < 3
  /\ guest' = g /\ vmid' = Vmid(g) /\ root' = Root(g) /\ mode' = "Sv39x4"
  /\ epoch' = epoch + 1 /\ phase' = "Dirty" /\ translationUsed' = FALSE
  /\ UNCHANGED fencedEpoch
Modify == /\ phase = "Active" /\ epoch < 3 /\ phase' = "Dirty" /\ epoch' = epoch + 1
  /\ translationUsed' = FALSE /\ UNCHANGED <<guest,vmid,root,mode,fencedEpoch>>
Fence == /\ phase = "Dirty" /\ phase' = "Fenced" /\ fencedEpoch' = epoch
  /\ UNCHANGED <<guest,vmid,root,mode,epoch,translationUsed>>
Activate == /\ phase = "Fenced" /\ fencedEpoch = epoch
  /\ phase' = "Active" /\ UNCHANGED <<guest,vmid,root,mode,epoch,fencedEpoch,translationUsed>>
Translate == /\ phase = "Active" /\ fencedEpoch = epoch /\ mode = "Sv39x4"
  /\ root = Root(guest) /\ vmid = Vmid(guest) /\ translationUsed' = TRUE
  /\ UNCHANGED <<phase,guest,vmid,root,mode,epoch,fencedEpoch>>
Switch == /\ phase = "Active" /\ phase' = "Idle" /\ guest' = "None"
  /\ vmid' = 0 /\ root' = "None" /\ mode' = "Bare" /\ translationUsed' = FALSE
  /\ UNCHANGED <<epoch,fencedEpoch>>
Done == /\ phase = "Idle" /\ epoch = 3 /\ UNCHANGED vars
Next == (\E g \in {{"guest1","guest2"}}: Configure(g)) \/ Modify \/ Fence
        \/ Activate \/ Translate \/ Switch \/ Done
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {{"Idle","Dirty","Fenced","Active"}}
  /\ guest \in {{"None","guest1","guest2"}} /\ vmid \in 0..2
  /\ root \in {{"None","Root1","Root2"}} /\ mode \in {{"Bare","Sv39x4"}}
  /\ epoch \in 0..3 /\ fencedEpoch \in 0..3
TranslationRequiresFence == translationUsed => phase = "Active" /\ fencedEpoch = epoch
ActiveContextReviewed == phase = "Active" =>
  /\ guest \in {{"guest1","guest2"}} /\ mode = "Sv39x4"
  /\ root = Root(guest) /\ vmid = Vmid(guest)
DirtyCannotTranslate == phase = "Dirty" => ~translationUsed
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\n"
           "INVARIANT TranslationRequiresFence\nINVARIANT ActiveContextReviewed\n"
           "INVARIANT DirtyCannotTranslate\n")
    return tla, cfg

def run_gstage_lifecycle(plan: dict[str, Any]) -> dict[str, Any]:
    try:
        tla, cfg = render_gstage_lifecycle(plan)
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name="RiscvGStageLifecycle",
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

def run_gstage_mutation(plan: dict[str, Any], mutation: str) -> dict[str, Any]:
    tla, cfg = render_gstage_lifecycle(plan)
    bad = {
        "missing_hfence": r'''Bad == /\ phase = "Dirty" /\ phase' = "Active"
  /\ translationUsed' = TRUE
  /\ UNCHANGED <<guest,vmid,root,mode,epoch,fencedEpoch>>
''',
        "wrong_root": r'''Bad == /\ phase = "Fenced" /\ guest = "guest1"
  /\ phase' = "Active" /\ root' = "Root2"
  /\ UNCHANGED <<guest,vmid,mode,epoch,fencedEpoch,translationUsed>>
''',
        "bare_active": r'''Bad == /\ phase = "Fenced" /\ phase' = "Active"
  /\ mode' = "Bare"
  /\ UNCHANGED <<guest,vmid,root,epoch,fencedEpoch,translationUsed>>
''',
    }.get(mutation)
    if bad is None:
        return _fail("RISCV_G_STAGE_MUTATION_UNKNOWN", mutation)
    tla = tla.replace("Next == ", bad + "Next == Bad \\/ ", 1)
    result = run_tlc_artifacts(tla, cfg, module_name="RiscvGStageLifecycle",
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

def validate_gstage_claim(artifact: dict[str, Any], root: str | Path) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        plan, plan_hash = _load(base, artifact["reviewed_plan"], "RISCV_G_STAGE_PLAN")
        guest_artifact, _ = _load(base, artifact["guest_transition_artifact"],
                                  "RISCV_GUEST_TRANSITION_ARTIFACT")
        guest_evidence, guest_hash = _load(base, artifact["guest_transition_evidence"],
                                          "RISCV_GUEST_TRANSITION_EVIDENCE")
        if verify_guest_evidence(guest_artifact, base, guest_evidence).get("claim") != \
                "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED":
            return _fail("RISCV_G_STAGE_GUEST_DEPENDENCY_UNPROVED")
        failures = validate_gstage_plan(plan, reviewed=True)
        if failures:
            return _fail("RISCV_G_STAGE_PLAN_INVALID", ",".join(failures))
        result = run_gstage_lifecycle(plan)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("RISCV_G_STAGE_TLC_FAILED")
    return {"status": "RISCV_G_STAGE_ISOLATION_PROVED", "claim": CLAIM,
            "judge": "deterministic_sv39x4_gate+tlc", "scope": SCOPE,
            "reviewed_plan_sha256": plan_hash,
            "guest_transition_evidence_sha256": guest_hash,
            "tlc_version": result["tlc_version"],
            "generated_tla_sha256": result["generated_tla_sha256"],
            "generated_cfg_sha256": result["generated_cfg_sha256"],
            "distinct_states": result["distinct_states"],
            "properties": ["GUEST_SPA_OWNERSHIP", "GUEST_GUEST_DISJOINTNESS",
                           "GUEST_HS_DISJOINTNESS", "VS_WALK_PAGE_OWNERSHIP",
                           "SV39X4_ROOT_16K_ALIGNED", "ACTIVE_VMID_SEPARATION",
                           "REVIEWED_HGATP_ROOT", "HFENCE_GVMA_EPOCH_REQUIRED",
                           "BARE_MODE_REJECTED", "GPA_BOUNDED"],
            "vmidlen_assumption": plan["vmidlen_assumption"],
            "g_stage_tlb_coherence_proved": False,
            "hardware_g_stage_walk_proved": False,
            "compiled_hgatp_refinement_proved": False,
            "qemu_g_stage_semantics_proved": False,
            "physical_guest_memory_isolation_proved": False}

def write_gstage_evidence(path: str | Path, evidence: dict[str, Any]) -> None:
    if evidence.get("claim") != CLAIM:
        raise ValueError("RISCV_G_STAGE_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")

def verify_gstage_evidence(artifact: dict[str, Any], root: str | Path,
                           evidence: dict[str, Any]) -> dict[str, Any]:
    base = Path(root).resolve()
    try:
        plan, plan_hash = _load(base, artifact["reviewed_plan"], "RISCV_G_STAGE_PLAN")
        guest_artifact, _ = _load(base, artifact["guest_transition_artifact"],
                                  "RISCV_GUEST_TRANSITION_ARTIFACT")
        guest_evidence, guest_hash = _load(base, artifact["guest_transition_evidence"],
                                          "RISCV_GUEST_TRANSITION_EVIDENCE")
        if validate_gstage_plan(plan, reviewed=True):
            return _fail("RISCV_G_STAGE_REVIEWED_PLAN_INVALID")
        if plan.get("accepted_candidate_sha256") != \
                "ba8b2d846ecb04878c1ef848fc529b726eee576581d9ca5e97932ef4380c9325":
            return _fail("RISCV_G_STAGE_ACCEPTED_CANDIDATE_MISMATCH")
        if verify_guest_evidence(guest_artifact, base, guest_evidence).get("claim") != \
                "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED":
            return _fail("RISCV_G_STAGE_GUEST_DEPENDENCY_UNPROVED")
        tla, cfg = render_gstage_lifecycle(plan)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    properties = {"GUEST_SPA_OWNERSHIP", "GUEST_GUEST_DISJOINTNESS",
                  "GUEST_HS_DISJOINTNESS", "VS_WALK_PAGE_OWNERSHIP",
                  "SV39X4_ROOT_16K_ALIGNED", "ACTIVE_VMID_SEPARATION",
                  "REVIEWED_HGATP_ROOT", "HFENCE_GVMA_EPOCH_REQUIRED",
                  "BARE_MODE_REJECTED", "GPA_BOUNDED"}
    valid = (
        evidence.get("status") == "RISCV_G_STAGE_ISOLATION_PROVED"
        and evidence.get("claim") == CLAIM
        and evidence.get("judge") == "deterministic_sv39x4_gate+tlc"
        and evidence.get("scope") == SCOPE
        and evidence.get("reviewed_plan_sha256") == plan_hash
        and evidence.get("guest_transition_evidence_sha256") == guest_hash
        and evidence.get("generated_tla_sha256") == _sha(tla.encode())
        and evidence.get("generated_cfg_sha256") == _sha(cfg.encode())
        and evidence.get("vmidlen_assumption") == 7
        and set(evidence.get("properties", [])) == properties
        and all(evidence.get(key) is False for key in (
            "g_stage_tlb_coherence_proved", "hardware_g_stage_walk_proved",
            "compiled_hgatp_refinement_proved", "qemu_g_stage_semantics_proved",
            "physical_guest_memory_isolation_proved")))
    if not valid:
        return _fail("RISCV_G_STAGE_EVIDENCE_BINDING_MISMATCH")
    return {"status": "RISCV_G_STAGE_EVIDENCE_BOUND", "claim": CLAIM,
            "scope": SCOPE, "reviewed_plan_sha256": plan_hash,
            "guest_transition_evidence_sha256": guest_hash,
            "distinct_states": evidence.get("distinct_states")}
