# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M62: bounded EL1/EL0 exception-transition model judged by TLC."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import config
from .domain_v2_tools import (get_tlc_provenance, require_tlc_provenance,
                              run_tlc_artifacts)


def _fail(code: str, message: str = "") -> dict:
    return {"status": "EXCEPTION_TRANSITION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_exception_transition(module: str = "ExceptionLevelTransition") -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("EXCEPTION_MODULE_INVALID")
    tla = f"""---- MODULE {module} ----
EXTENDS Naturals
VARIABLES mode, phase, spsr, elrClass, mmuOn, dispatchChecked, hasTrapped
vars == <<mode, phase, spsr, elrClass, mmuOn, dispatchChecked, hasTrapped>>

Init == /\\ mode = "EL1"
        /\\ phase = "Boot"
        /\\ spsr = "EL1h"
        /\\ elrClass = "Kernel"
        /\\ mmuOn = FALSE
        /\\ dispatchChecked = FALSE
        /\\ hasTrapped = FALSE

PrepareUser == /\\ mode = "EL1" /\\ phase = "Boot"
               /\\ mode' = mode /\\ phase' = "Prepared"
               /\\ spsr' = "EL0t" /\\ elrClass' = "User"
               /\\ mmuOn' = TRUE /\\ dispatchChecked' = FALSE
               /\\ hasTrapped' = hasTrapped

EretToUser == /\\ mode = "EL1" /\\ phase = "Prepared"
              /\\ spsr = "EL0t" /\\ elrClass = "User" /\\ mmuOn
              /\\ mode' = "EL0" /\\ phase' = "Running"
              /\\ UNCHANGED <<spsr, elrClass, mmuOn, dispatchChecked, hasTrapped>>

SyscallTrap == /\\ mode = "EL0" /\\ phase = "Running"
               /\\ mode' = "EL1" /\\ phase' = "TrapEntry"
               /\\ spsr' = "EL0t" /\\ elrClass' = "User"
               /\\ mmuOn' = mmuOn /\\ dispatchChecked' = FALSE
               /\\ hasTrapped' = TRUE

ValidateDispatch == /\\ mode = "EL1" /\\ phase = "TrapEntry"
                    /\\ mode' = mode /\\ phase' = "DispatchChecked"
                    /\\ dispatchChecked' = TRUE
                    /\\ UNCHANGED <<spsr, elrClass, mmuOn, hasTrapped>>

ReturnFromSyscall == /\\ mode = "EL1" /\\ phase = "DispatchChecked"
                     /\\ dispatchChecked /\\ spsr = "EL0t"
                     /\\ elrClass = "User" /\\ mmuOn
                     /\\ mode' = "EL0" /\\ phase' = "Running"
                     /\\ UNCHANGED <<spsr, elrClass, mmuOn, dispatchChecked, hasTrapped>>

Next == PrepareUser \\/ EretToUser \\/ SyscallTrap \\/ ValidateDispatch \\/ ReturnFromSyscall
Spec == Init /\\ [][Next]_vars
TypeOK == /\\ mode \\in {{"EL0", "EL1"}}
          /\\ phase \\in {{"Boot", "Prepared", "Running", "TrapEntry", "DispatchChecked"}}
          /\\ spsr \\in {{"EL0t", "EL1h"}}
          /\\ elrClass \\in {{"User", "Kernel"}}
EL0RequiresPreparedReturn == mode = "EL0" =>
  /\\ phase = "Running" /\\ spsr = "EL0t" /\\ elrClass = "User" /\\ mmuOn
TrappedReturnRequiresDispatch == (mode = "EL0" /\\ hasTrapped) => dispatchChecked
====
"""
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\n"
           "INVARIANT EL0RequiresPreparedReturn\n"
           "INVARIANT TrappedReturnRequiresDispatch\n")
    return tla, cfg


def _binding_hashes(root: Path, artifact: dict) -> dict[str, str]:
    bindings = artifact.get("bindings")
    if not isinstance(bindings, dict) or not bindings:
        raise ValueError("EXCEPTION_BINDINGS_INVALID")
    actual = {}
    for name, binding in bindings.items():
        if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
            raise ValueError("EXCEPTION_BINDINGS_INVALID")
        path = (root / binding["path"]).resolve()
        if root.resolve() not in path.parents or not path.is_file():
            raise ValueError("EXCEPTION_BINDING_PATH_INVALID")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != binding["sha256"]:
            raise ValueError("EXCEPTION_BINDING_HASH_MISMATCH")
        actual[name] = digest
    return actual


def validate_exception_transition(artifact: dict, root: str | Path) -> dict:
    try:
        bindings = _binding_hashes(Path(root), artifact)
        tla, cfg = render_exception_transition(artifact.get("module", ""))
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=artifact["module"],
                                   tlc_jar=config.TLC_JAR,
                                   java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("EXCEPTION_TLC_FAILED", result.get("output", ""))
    output = result.get("output", "")
    distinct = re.search(r"(\d+) distinct states found", output)
    return {
        "status": "EXCEPTION_TRANSITION_MODEL_PROVED",
        "claim": "EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED", "judge": "tlc",
        "tlc_version": provenance["version"], "bindings": bindings,
        "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest(),
        "distinct_states": int(distinct.group(1)) if distinct else None,
        "properties": ["TYPE_SAFE", "EL0_REQUIRES_PREPARED_RETURN",
                       "TRAPPED_RETURN_REQUIRES_DISPATCH"],
        "hardware_eret_semantics_proved": False,
        "compiled_vector_refinement_proved": False,
    }


def write_exception_validation(path: str | Path, evidence: dict) -> None:
    if evidence.get("status") != "EXCEPTION_TRANSITION_MODEL_PROVED":
        raise ValueError("EXCEPTION_VALIDATION_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def verify_exception_evidence(artifact: dict, root: str | Path,
                              evidence: dict) -> dict:
    try:
        bindings = _binding_hashes(Path(root), artifact)
        tla, _ = render_exception_transition(artifact.get("module", ""))
    except (OSError, TypeError, ValueError) as exc:
        return _fail(str(exc))
    valid = (evidence.get("status") == "EXCEPTION_TRANSITION_MODEL_PROVED"
             and evidence.get("judge") == "tlc"
             and evidence.get("bindings") == bindings
             and evidence.get("generated_tla_sha256") ==
             hashlib.sha256(tla.encode()).hexdigest()
             and set(evidence.get("properties", [])) == {
                 "TYPE_SAFE", "EL0_REQUIRES_PREPARED_RETURN",
                 "TRAPPED_RETURN_REQUIRES_DISPATCH"}
             and evidence.get("hardware_eret_semantics_proved") is False
             and evidence.get("compiled_vector_refinement_proved") is False)
    if not valid:
        return _fail("EXCEPTION_EVIDENCE_BINDING_MISMATCH")
    return {"status": "EXCEPTION_TRANSITION_EVIDENCE_BOUND",
            "claim": "EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED",
            "bindings": bindings,
            "generated_tla_sha256": evidence["generated_tla_sha256"],
            "tlc_version": evidence.get("tlc_version"),
            "distinct_states": evidence.get("distinct_states")}
