# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M73 bounded adversarial TCP resource-containment model."""
from __future__ import annotations

import hashlib
import json
import re

from . import config
from .domain_v2_tools import (get_tlc_provenance, require_tlc_provenance,
                              run_tlc_artifacts)


ENVELOPE = {"duplicate_syn", "dropped_ack", "reordered_ack", "blind_rst",
            "retransmission_timeout", "time_wait_pressure"}


def _fail(code: str, message: str = "") -> dict:
    return {"status": "TCP_RESOURCE_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_tcp_resource_model(module: str, pool: int, quota: int,
                              modulus: int, window: int) -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("TCP_RESOURCE_MODULE_INVALID")
    if (pool, quota, modulus, window) != (4, 2, 8, 2):
        raise ValueError("TCP_RESOURCE_BOUND_MISMATCH")
    tla = f'''---- MODULE {module} ----
EXTENDS Naturals, FiniteSets
CONSTANT PoolCap, ClientQuota, SeqMod, RecvWindow
ASSUME /\\ PoolCap = {pool} /\\ ClientQuota = {quota}
       /\\ SeqMod = {modulus} /\\ RecvWindow = {window}
Clients == {{"Attacker", "Legit"}}
VARIABLES halfOpen, established, timeWait, expectedSeq, lastAck, challengeAcks
vars == <<halfOpen, established, timeWait, expectedSeq, lastAck, challengeAcks>>

Usage(c) == halfOpen[c] + established[c] + timeWait[c]
TotalUsage == Usage("Attacker") + Usage("Legit")
InWindow(ack, expected) == (ack + SeqMod - expected) % SeqMod < RecvWindow

Init == /\\ halfOpen = [c \\in Clients |-> 0]
        /\\ established = [c \\in Clients |-> 0]
        /\\ timeWait = [c \\in Clients |-> 0]
        /\\ expectedSeq = [c \\in Clients |-> 0]
        /\\ lastAck = [c \\in Clients |-> 0]
        /\\ challengeAcks = 0

Syn(c) == /\\ c \\in Clients /\\ Usage(c) < ClientQuota
          /\\ TotalUsage < PoolCap
          /\\ halfOpen' = [halfOpen EXCEPT ![c] = @ + 1]
          /\\ expectedSeq' = [expectedSeq EXCEPT ![c] = (@ + 1) % SeqMod]
          /\\ UNCHANGED <<established, timeWait, lastAck, challengeAcks>>

DuplicateSyn(c) == /\\ c \\in Clients /\\ halfOpen[c] > 0
                   /\\ UNCHANGED vars

ValidAck(c) == /\\ c \\in Clients /\\ halfOpen[c] > 0
               /\\ InWindow(expectedSeq[c], expectedSeq[c])
               /\\ halfOpen' = [halfOpen EXCEPT ![c] = @ - 1]
               /\\ established' = [established EXCEPT ![c] = @ + 1]
               /\\ lastAck' = [lastAck EXCEPT ![c] = expectedSeq[c]]
               /\\ UNCHANGED <<timeWait, expectedSeq, challengeAcks>>

ReorderedAck(c) == /\\ c \\in Clients /\\ halfOpen[c] > 0
                   /\\ ~InWindow((expectedSeq[c] + SeqMod - 1) % SeqMod,
                                  expectedSeq[c])
                   /\\ UNCHANGED vars

DroppedAck(c) == /\\ c \\in Clients /\\ halfOpen[c] > 0
                 /\\ UNCHANGED vars

RetransmitTimeout(c) == /\\ c \\in Clients /\\ halfOpen[c] > 0
                        /\\ halfOpen' = [halfOpen EXCEPT ![c] = @ - 1]
                        /\\ UNCHANGED <<established, timeWait, expectedSeq,
                                        lastAck, challengeAcks>>

Close(c) == /\\ c \\in Clients /\\ established[c] > 0
            /\\ established' = [established EXCEPT ![c] = @ - 1]
            /\\ timeWait' = [timeWait EXCEPT ![c] = @ + 1]
            /\\ UNCHANGED <<halfOpen, expectedSeq, lastAck, challengeAcks>>

ExpireTimeWait(c) == /\\ c \\in Clients /\\ timeWait[c] > 0
                     /\\ timeWait' = [timeWait EXCEPT ![c] = @ - 1]
                     /\\ UNCHANGED <<halfOpen, established, expectedSeq,
                                     lastAck, challengeAcks>>

BlindRst(c) == /\\ c \\in Clients /\\ established[c] > 0
               /\\ challengeAcks' = (challengeAcks + 1) % 3
               /\\ UNCHANGED <<halfOpen, established, timeWait,
                               expectedSeq, lastAck>>

Next == \\/ \\E c \\in Clients : Syn(c)
        \\/ \\E c \\in Clients : DuplicateSyn(c)
        \\/ \\E c \\in Clients : ValidAck(c)
        \\/ \\E c \\in Clients : ReorderedAck(c)
        \\/ \\E c \\in Clients : DroppedAck(c)
        \\/ \\E c \\in Clients : RetransmitTimeout(c)
        \\/ \\E c \\in Clients : Close(c)
        \\/ \\E c \\in Clients : ExpireTimeWait(c)
        \\/ \\E c \\in Clients : BlindRst(c)
Spec == Init /\\ [][Next]_vars

TypeOK == /\\ halfOpen \\in [Clients -> 0..ClientQuota]
          /\\ established \\in [Clients -> 0..ClientQuota]
          /\\ timeWait \\in [Clients -> 0..ClientQuota]
          /\\ expectedSeq \\in [Clients -> 0..(SeqMod - 1)]
          /\\ lastAck \\in [Clients -> 0..(SeqMod - 1)]
          /\\ challengeAcks \\in 0..2
PoolBound == TotalUsage <= PoolCap
PerClientQuota == \\A c \\in Clients : Usage(c) <= ClientQuota
LegitimateReserve == PoolCap - Usage("Attacker") >= ClientQuota
BlindRstContained == challengeAcks \\in 0..2
====
'''
    cfg = (f"CONSTANT PoolCap = {pool}\nCONSTANT ClientQuota = {quota}\n"
           f"CONSTANT SeqMod = {modulus}\nCONSTANT RecvWindow = {window}\n"
           "SPECIFICATION Spec\nINVARIANT TypeOK\nINVARIANT PoolBound\n"
           "INVARIANT PerClientQuota\nINVARIANT LegitimateReserve\n"
           "INVARIANT BlindRstContained\n")
    return tla, cfg


def _artifact_valid(artifact: dict) -> bool:
    return (artifact.get("clients") == ["Attacker", "Legit"]
            and artifact.get("pool_capacity") == 4
            and artifact.get("per_client_quota") == 2
            and artifact.get("sequence_modulus") == 8
            and artifact.get("receive_window") == 2
            and set(artifact.get("adversarial_envelope", [])) == ENVELOPE
            and artifact.get("rfc9293_conformance_proved") is False
            and artifact.get("rfc5961_conformance_proved") is False
            and artifact.get("implementation_refinement_proved") is False)


def validate_tcp_resource(artifact: dict) -> dict:
    try:
        if not _artifact_valid(artifact):
            raise ValueError("TCP_RESOURCE_ARTIFACT_MISMATCH")
        tla, cfg = render_tcp_resource_model(
            artifact.get("module", ""), artifact["pool_capacity"],
            artifact["per_client_quota"], artifact["sequence_modulus"],
            artifact["receive_window"])
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=artifact["module"],
                                   tlc_jar=config.TLC_JAR,
                                   java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("TCP_RESOURCE_TLC_FAILED", result.get("output", ""))
    output = result.get("output", "")
    distinct = re.search(r"(\d+) distinct states found", output)
    return {
        "status": "TCP_RESOURCE_CONTAINMENT_PROVED",
        "claim": "TCP_RESOURCE_CONTAINMENT_PROVED", "judge": "tlc",
        "scope": "bounded_adversarial_network_and_partitioned_quotas",
        "tlc_version": provenance["version"],
        "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest(),
        "distinct_states": int(distinct.group(1)) if distinct else None,
        "properties": ["TYPE_OK", "POOL_BOUND", "PER_CLIENT_QUOTA",
                       "LEGITIMATE_RESERVE", "BLIND_RST_CONTAINED"],
        "rfc9293_conformance_proved": False,
        "rfc5961_conformance_proved": False,
        "implementation_refinement_proved": False,
    }


def verify_tcp_resource_evidence(artifact: dict, evidence: dict) -> dict:
    try:
        if not _artifact_valid(artifact):
            raise ValueError("TCP_RESOURCE_ARTIFACT_MISMATCH")
        tla, _ = render_tcp_resource_model(
            artifact.get("module", ""), artifact["pool_capacity"],
            artifact["per_client_quota"], artifact["sequence_modulus"],
            artifact["receive_window"])
    except (KeyError, TypeError, ValueError) as exc:
        return _fail(str(exc))
    valid = (evidence.get("status") == "TCP_RESOURCE_CONTAINMENT_PROVED"
             and evidence.get("judge") == "tlc"
             and evidence.get("generated_tla_sha256") ==
             hashlib.sha256(tla.encode()).hexdigest()
             and set(evidence.get("properties", [])) == {
                 "TYPE_OK", "POOL_BOUND", "PER_CLIENT_QUOTA",
                 "LEGITIMATE_RESERVE", "BLIND_RST_CONTAINED"}
             and evidence.get("rfc9293_conformance_proved") is False
             and evidence.get("rfc5961_conformance_proved") is False
             and evidence.get("implementation_refinement_proved") is False)
    if not valid:
        return _fail("TCP_RESOURCE_EVIDENCE_BINDING_MISMATCH")
    return {**evidence, "status": "TCP_RESOURCE_EVIDENCE_BOUND"}
