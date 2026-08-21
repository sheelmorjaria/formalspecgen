# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M72 bounded VFS journal crash semantics judged by real TLC."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import config
from .domain_v2_tools import (get_tlc_provenance, require_tlc_provenance,
                              run_tlc_artifacts)


def _fail(code: str, message: str = "") -> dict:
    return {"status": "VFS_CRASH_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_vfs_crash_model(module: str) -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("VFS_CRASH_MODULE_INVALID")
    tla = f'''---- MODULE {module} ----
EXTENDS Naturals, FiniteSets
VARIABLES fs, log, pending, phase, recoveryTarget, dataIssued
vars == <<fs, log, pending, phase, recoveryTarget, dataIssued>>

Writes == {{"Intent", "Data", "Commit"}}
LogStates == {{"Empty", "Intent", "Commit", "Torn"}}
Phases == {{"Idle", "Active", "Recovering", "RecoveringClear", "Done"}}

Init == /\\ fs = 0 /\\ log = "Empty" /\\ pending = {{}}
        /\\ phase = "Idle" /\\ recoveryTarget = 0 /\\ dataIssued = FALSE

Begin == /\\ phase = "Idle"
         /\\ phase' = "Active" /\\ pending' = {{"Intent"}}
         /\\ dataIssued' = FALSE
         /\\ UNCHANGED <<fs, log, recoveryTarget>>

IssueData == /\\ phase = "Active" /\\ ~dataIssued
             /\\ pending' = pending \\cup {{"Data"}}
             /\\ dataIssued' = TRUE
             /\\ UNCHANGED <<fs, log, phase, recoveryTarget>>

FlushIntent == /\\ phase = "Active" /\\ "Intent" \\in pending
               /\\ pending' = pending \\ {{"Intent"}}
               /\\ log' \\in {{"Intent", "Torn"}}
               /\\ UNCHANGED <<fs, phase, recoveryTarget, dataIssued>>

FlushData == /\\ phase = "Active" /\\ "Data" \\in pending
             /\\ pending' = pending \\ {{"Data"}}
             /\\ fs' \\in {{1, 2}}
             /\\ UNCHANGED <<log, phase, recoveryTarget, dataIssued>>

IssueCommit == /\\ phase = "Active" /\\ log = "Intent" /\\ fs = 1
               /\\ "Commit" \\notin pending
               /\\ pending' = pending \\cup {{"Commit"}}
               /\\ UNCHANGED <<fs, log, phase, recoveryTarget, dataIssued>>

FlushCommit == /\\ phase = "Active" /\\ "Commit" \\in pending
               /\\ pending' = pending \\ {{"Commit"}}
               /\\ log' \\in {{"Commit", "Torn"}}
               /\\ UNCHANGED <<fs, phase, recoveryTarget, dataIssued>>

Crash == /\\ phase \\in {{"Active", "RecoveringClear"}}
         /\\ phase' = "Recovering" /\\ pending' = {{}}
         /\\ UNCHANGED <<fs, log, recoveryTarget, dataIssued>>

RecoveryWrite == /\\ phase = "Recovering"
                 /\\ recoveryTarget' = IF log = "Commit" /\\ fs = 1 THEN 1 ELSE 0
                 /\\ fs' = recoveryTarget' /\\ phase' = "RecoveringClear"
                 /\\ UNCHANGED <<log, pending, dataIssued>>

RecoveryClear == /\\ phase = "RecoveringClear"
                 /\\ log' = "Empty" /\\ phase' = "Done"
                 /\\ UNCHANGED <<fs, pending, recoveryTarget, dataIssued>>

Quiesce == /\\ phase = "Done" /\\ UNCHANGED vars
Next == Begin \\/ IssueData \\/ FlushIntent \\/ FlushData \\/ IssueCommit
        \\/ FlushCommit \\/ Crash \\/ RecoveryWrite \\/ RecoveryClear \\/ Quiesce
Spec == Init /\\ [][Next]_vars

TypeOK == /\\ fs \\in 0..2 /\\ log \\in LogStates
          /\\ pending \\subseteq Writes /\\ phase \\in Phases
          /\\ recoveryTarget \\in {{0, 1}} /\\ dataIssued \\in BOOLEAN
CommitImpliesNew == log = "Commit" => fs = 1
RecoveryWriteStable == phase = "RecoveringClear" => fs = recoveryTarget
CrashAtomicity == phase = "Done" => fs \\in {{0, 1}}
====
'''
    cfg = ("SPECIFICATION Spec\nINVARIANT TypeOK\n"
           "INVARIANT CommitImpliesNew\nINVARIANT RecoveryWriteStable\n"
           "INVARIANT CrashAtomicity\n")
    return tla, cfg


def _contract_valid(artifact: dict) -> bool:
    return artifact.get("persistence_contract") == {
        "old_state": 0, "new_state": 1, "torn_state": 2,
        "intent_and_data_may_reorder": True,
        "commit_requires_durable_intent_and_data": True,
        "volatile_cache_lost_on_crash": True,
        "recovery_may_crash": True}


def validate_vfs_crash(artifact: dict) -> dict:
    try:
        if not _contract_valid(artifact):
            raise ValueError("VFS_PERSISTENCE_CONTRACT_MISMATCH")
        tla, cfg = render_vfs_crash_model(artifact.get("module", ""))
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=artifact["module"],
                                   tlc_jar=config.TLC_JAR,
                                   java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("VFS_CRASH_TLC_FAILED", result.get("output", ""))
    output = result.get("output", "")
    distinct = re.search(r"(\d+) distinct states found", output)
    return {
        "status": "FILESYSTEM_CRASH_ATOMICITY_PROVED",
        "claim": "FILESYSTEM_CRASH_ATOMICITY_PROVED",
        "judge": "tlc", "scope": "declared_persistence_contract",
        "tlc_version": provenance["version"],
        "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest(),
        "distinct_states": int(distinct.group(1)) if distinct else None,
        "properties": ["TYPE_OK", "COMMIT_IMPLIES_NEW",
                       "RECOVERY_WRITE_STABLE", "CRASH_ATOMICITY"],
        "physical_fua_semantics_proved": False,
        "device_firmware_proved": False,
        "crash_injection_validated": False,
    }


def verify_vfs_crash_evidence(artifact: dict, evidence: dict) -> dict:
    try:
        if not _contract_valid(artifact):
            raise ValueError("VFS_PERSISTENCE_CONTRACT_MISMATCH")
        tla, _cfg = render_vfs_crash_model(artifact.get("module", ""))
    except (TypeError, ValueError) as exc:
        return _fail(str(exc))
    valid = (evidence.get("status") == "FILESYSTEM_CRASH_ATOMICITY_PROVED"
             and evidence.get("judge") == "tlc"
             and evidence.get("scope") == "declared_persistence_contract"
             and evidence.get("generated_tla_sha256") ==
             hashlib.sha256(tla.encode()).hexdigest()
             and set(evidence.get("properties", [])) == {
                 "TYPE_OK", "COMMIT_IMPLIES_NEW", "RECOVERY_WRITE_STABLE",
                 "CRASH_ATOMICITY"}
             and evidence.get("physical_fua_semantics_proved") is False
             and evidence.get("device_firmware_proved") is False
             and evidence.get("crash_injection_validated") is False)
    if not valid:
        return _fail("VFS_CRASH_EVIDENCE_BINDING_MISMATCH")
    return {**evidence, "status": "VFS_CRASH_EVIDENCE_BOUND"}
