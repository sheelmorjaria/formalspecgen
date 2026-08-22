# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.2: RISC-V S-mode/U-mode trap-return control-state model."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import config
from .domain_v2_tools import (get_tlc_provenance, require_tlc_provenance,
                              run_tlc_artifacts)


CLAIM = "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED"
STATUS = "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED"
PROPERTIES = {
    "TYPE_SAFE", "USER_REQUIRES_REVIEWED_PREPARATION",
    "TRAP_RETURN_REQUIRES_VALIDATED_DISPATCH",
    "USER_CANNOT_SELECT_SUPERVISOR_RESUME",
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(code: str, message: str = "") -> dict[str, Any]:
    return {"status": "RISCV_PRIVILEGE_TRANSITION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_riscv_privilege_transition(
        module: str = "RiscvPrivilegeTransition") -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("RISCV_PRIVILEGE_MODULE_INVALID")
    tla = f'''---- MODULE {module} ----
EXTENDS Naturals
VARIABLES mode, phase, satpMode, satpRoot, stvecReady, spp, sepcClass,
          dispatchValidated, hasTrapped, requestedResume
vars == <<mode, phase, satpMode, satpRoot, stvecReady, spp, sepcClass,
          dispatchValidated, hasTrapped, requestedResume>>

Init == /\\ mode = "S"
        /\\ phase = "Boot"
        /\\ satpMode = "Bare"
        /\\ satpRoot = "None"
        /\\ stvecReady = FALSE
        /\\ spp = "S"
        /\\ sepcClass = "Supervisor"
        /\\ dispatchValidated = FALSE
        /\\ hasTrapped = FALSE
        /\\ requestedResume = "U"

PrepareUser == /\\ mode = "S" /\\ phase = "Boot"
               /\\ mode' = mode /\\ phase' = "Prepared"
               /\\ satpMode' = "Sv39" /\\ stvecReady' = TRUE
               /\\ satpRoot' = "ReviewedRoot"
               /\\ spp' = "U" /\\ sepcClass' = "User"
               /\\ dispatchValidated' = FALSE
               /\\ hasTrapped' = hasTrapped
               /\\ requestedResume' = "U"

SretToUser == /\\ mode = "S" /\\ phase = "Prepared"
              /\\ satpMode = "Sv39" /\\ stvecReady
              /\\ spp = "U" /\\ sepcClass = "User"
              /\\ mode' = "U" /\\ phase' = "Running"
              /\\ satpRoot = "ReviewedRoot"
              /\\ UNCHANGED <<satpMode, satpRoot, stvecReady, spp, sepcClass,
                              dispatchValidated, hasTrapped, requestedResume>>

UserTrap == /\\ mode = "U" /\\ phase = "Running"
            /\\ requestedResume' \\in {{"U", "S"}}
            /\\ mode' = "S" /\\ phase' = "TrapEntry"
            /\\ satpMode' = satpMode /\\ satpRoot' = satpRoot /\\ stvecReady' = stvecReady
            /\\ spp' = "U" /\\ sepcClass' = "User"
            /\\ dispatchValidated' = FALSE /\\ hasTrapped' = TRUE

ValidateDispatch == /\\ mode = "S" /\\ phase = "TrapEntry"
                    /\\ requestedResume = "U"
                    /\\ mode' = mode /\\ phase' = "DispatchChecked"
                    /\\ dispatchValidated' = TRUE
                    /\\ UNCHANGED <<satpMode, satpRoot, stvecReady, spp, sepcClass,
                                    hasTrapped, requestedResume>>

RejectSupervisorResume == /\\ mode = "S" /\\ phase = "TrapEntry"
                          /\\ requestedResume = "S"
                          /\\ mode' = mode /\\ phase' = "Rejected"
                          /\\ UNCHANGED <<satpMode, satpRoot, stvecReady, spp, sepcClass,
                                          dispatchValidated, hasTrapped,
                                          requestedResume>>

RemainRejected == /\\ mode = "S" /\\ phase = "Rejected"
                  /\\ UNCHANGED vars

ReturnToUser == /\\ mode = "S" /\\ phase = "DispatchChecked"
                /\\ dispatchValidated /\\ requestedResume = "U"
                /\\ satpMode = "Sv39" /\\ satpRoot = "ReviewedRoot" /\\ stvecReady
                /\\ spp = "U" /\\ sepcClass = "User"
                /\\ mode' = "U" /\\ phase' = "Running"
                /\\ UNCHANGED <<satpMode, satpRoot, stvecReady, spp, sepcClass,
                                dispatchValidated, hasTrapped, requestedResume>>

Next == PrepareUser \\/ SretToUser \\/ UserTrap \\/ ValidateDispatch
        \\/ RejectSupervisorResume \\/ RemainRejected \\/ ReturnToUser
Spec == Init /\\ [][Next]_vars

TypeOK == /\\ mode \\in {{"S", "U"}}
          /\\ phase \\in {{"Boot", "Prepared", "Running", "TrapEntry",
                            "DispatchChecked", "Rejected"}}
          /\\ satpMode \\in {{"Bare", "Sv39"}}
          /\\ satpRoot \\in {{"None", "ReviewedRoot"}}
          /\\ spp \\in {{"S", "U"}}
          /\\ sepcClass \\in {{"Supervisor", "User"}}
          /\\ requestedResume \\in {{"S", "U"}}

UserRequiresReviewedPreparation == mode = "U" =>
  /\\ phase = "Running" /\\ satpMode = "Sv39" /\\ satpRoot = "ReviewedRoot" /\\ stvecReady
  /\\ spp = "U" /\\ sepcClass = "User" /\\ requestedResume = "U"

TrappedReturnRequiresValidatedDispatch ==
  (mode = "U" /\\ hasTrapped) => dispatchValidated

UserCannotSelectSupervisorResume ==
  requestedResume = "S" => mode = "S"
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\n"
           "INVARIANT UserRequiresReviewedPreparation\n"
           "INVARIANT TrappedReturnRequiresValidatedDispatch\n"
           "INVARIANT UserCannotSelectSupervisorResume\n")
    return tla, cfg


def _reviewed_profile(root: Path, artifact: dict[str, Any]) -> tuple[dict, str]:
    binding = artifact.get("reviewed_profile")
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
        raise ValueError("RISCV_REVIEWED_PROFILE_BINDING_INVALID")
    path = (root / binding["path"]).resolve()
    if root.resolve() not in path.parents or not path.is_file():
        raise ValueError("RISCV_REVIEWED_PROFILE_PATH_INVALID")
    digest = _sha(path.read_bytes())
    if digest != binding["sha256"]:
        raise ValueError("RISCV_REVIEWED_PROFILE_HASH_MISMATCH")
    profile = json.loads(path.read_text(encoding="utf-8"))
    if (profile.get("status") != "REVIEWED_RISCV_PLATFORM_PROFILE"
            or profile.get("isa") != "RV64GC"
            or profile.get("page_table_mode") != "Sv39"
            or profile.get("privilege_modes") != ["M", "S", "U"]):
        raise ValueError("RISCV_REVIEWED_PROFILE_SCOPE_INVALID")
    return profile, digest


def validate_riscv_privilege_transition(artifact: dict[str, Any],
                                        root: str | Path) -> dict[str, Any]:
    try:
        profile, profile_hash = _reviewed_profile(Path(root), artifact)
        tla, cfg = render_riscv_privilege_transition(artifact["module"])
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=artifact["module"],
                                   tlc_jar=config.TLC_JAR, java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError,
            json.JSONDecodeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("RISCV_PRIVILEGE_TLC_FAILED", result.get("output", ""))
    output = result.get("output", "")
    distinct = re.search(r"(\d+) distinct states found", output)
    return {
        "status": STATUS, "claim": CLAIM, "judge": "tlc",
        "scope": "reviewed_qemu_virt_smode_umode_trap_return",
        "reviewed_profile_sha256": profile_hash,
        "accepted_profile_candidate_sha256": profile["accepted_candidate_sha256"],
        "generated_tla_sha256": _sha(tla.encode()),
        "generated_cfg_sha256": _sha(cfg.encode()),
        "tlc_output_sha256": _sha(output.encode()),
        "tlc_version": provenance["version"],
        "distinct_states": int(distinct.group(1)) if distinct else None,
        "properties": sorted(PROPERTIES),
        "qemu_semantics_proved": False,
        "hardware_privilege_transition_proved": False,
        "compiled_trap_vector_refinement_proved": False,
        "physical_execution_proved": False,
    }


def verify_riscv_privilege_evidence(artifact: dict[str, Any], root: str | Path,
                                    evidence: dict[str, Any]) -> dict[str, Any]:
    try:
        _, profile_hash = _reviewed_profile(Path(root), artifact)
        tla, cfg = render_riscv_privilege_transition(artifact["module"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    valid = (
        evidence.get("status") == STATUS and evidence.get("claim") == CLAIM
        and evidence.get("judge") == "tlc"
        and evidence.get("scope") == "reviewed_qemu_virt_smode_umode_trap_return"
        and evidence.get("reviewed_profile_sha256") == profile_hash
        and evidence.get("generated_tla_sha256") == _sha(tla.encode())
        and evidence.get("generated_cfg_sha256") == _sha(cfg.encode())
        and set(evidence.get("properties", [])) == PROPERTIES
        and all(evidence.get(field) is False for field in (
            "qemu_semantics_proved", "hardware_privilege_transition_proved",
            "compiled_trap_vector_refinement_proved", "physical_execution_proved")))
    if not valid:
        return _fail("RISCV_PRIVILEGE_EVIDENCE_BINDING_MISMATCH")
    return {"status": "RISCV_PRIVILEGE_TRANSITION_EVIDENCE_BOUND",
            "claim": CLAIM, "scope": evidence["scope"],
            "reviewed_profile_sha256": profile_hash,
            "generated_tla_sha256": evidence["generated_tla_sha256"],
            "distinct_states": evidence.get("distinct_states")}


def write_riscv_privilege_validation(path: str | Path,
                                     evidence: dict[str, Any]) -> None:
    if evidence.get("status") != STATUS:
        raise ValueError("RISCV_PRIVILEGE_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
