# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M59 bounded TLS handshake extraction model and real-TLC gate."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import config
from .domain_v2_tools import (get_tlc_provenance, require_tlc_provenance,
                              run_tlc_artifacts)


_NAME = re.compile(r"[A-Z][A-Za-z0-9]*\Z")


def _fail(code: str, message: str = "") -> dict:
    return {"status": "TLS_HANDSHAKE_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_tls_handshake(artifact: dict) -> tuple[str, str]:
    """Render the finite reviewed transition graph to deterministic TLA+."""
    module = artifact.get("module")
    states = artifact.get("states")
    initial = artifact.get("initial")
    terminals = artifact.get("terminal_states")
    transitions = artifact.get("transitions")
    if not isinstance(module, str) or not _NAME.fullmatch(module):
        raise ValueError("TLS_MODULE_INVALID")
    if not isinstance(states, list) or not states or len(states) > 8 \
            or len(set(states)) != len(states) \
            or not all(isinstance(item, str) and _NAME.fullmatch(item)
                       for item in states):
        raise ValueError("TLS_STATE_BOUND_INVALID")
    if initial not in states or not isinstance(terminals, list) or not terminals \
            or not set(terminals) <= set(states):
        raise ValueError("TLS_INITIAL_OR_TERMINAL_INVALID")
    if not isinstance(transitions, list) or not transitions or len(transitions) > 16:
        raise ValueError("TLS_TRANSITION_BOUND_INVALID")
    actions = []
    outgoing = {state: 0 for state in states}
    for transition in transitions:
        if not isinstance(transition, dict):
            raise ValueError("TLS_TRANSITION_INVALID")
        name, source, target = (transition.get("name"), transition.get("from"),
                                transition.get("to"))
        if not isinstance(name, str) or not _NAME.fullmatch(name) \
                or source not in states or target not in states:
            raise ValueError("TLS_TRANSITION_INVALID")
        outgoing[source] += 1
        actions.append(f'{name} == /\\ state = "{source}"\n'
                       f'          /\\ state\' = "{target}"')
    if any(count == 0 for count in outgoing.values()):
        raise ValueError("TLS_DEAD_END_STATE")
    state_set = "{" + ", ".join(f'\"{state}\"' for state in states) + "}"
    terminal_set = "{" + ", ".join(f'\"{state}\"' for state in terminals) + "}"
    next_names = " \\/ ".join(item["name"] for item in transitions)
    tla = (f"---- MODULE {module} ----\n"
           "EXTENDS Naturals\n"
           "VARIABLE state\n"
           "vars == <<state>>\n"
           f"States == {state_set}\n"
           f"TerminalStates == {terminal_set}\n"
           f"Init == state = \"{initial}\"\n\n" + "\n\n".join(actions) +
           f"\n\nNext == {next_names}\n"
           "Spec == Init /\\ [][Next]_vars /\\ WF_vars(Next)\n"
           "TypeOK == state \\in States\n"
           "Initialized == state \\in States\n"
           "EventuallyTerminal == <> (state \\in TerminalStates)\n"
           "====\n")
    cfg = ("SPECIFICATION Spec\n"
           "INVARIANT TypeOK\n"
           "INVARIANT Initialized\n"
           "PROPERTY EventuallyTerminal\n")
    return tla, cfg


def validate_tls_handshake(artifact: dict, source: bytes, *,
                           tlc_jar: str | None = None,
                           java: str | None = None) -> dict:
    """Bind the extracted graph to source bytes and discharge it with TLC."""
    digest = hashlib.sha256(source).hexdigest()
    if artifact.get("source_sha256") != digest:
        return _fail("TLS_SOURCE_HASH_MISMATCH")
    try:
        tla, cfg = render_tls_handshake(artifact)
        provenance = require_tlc_provenance(get_tlc_provenance(
            tlc_jar or config.TLC_JAR, java=java or config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=artifact["module"],
                                   tlc_jar=tlc_jar or config.TLC_JAR,
                                   java=java or config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("TLS_TLC_FAILED", result.get("output", ""))
    output = result.get("output", "")
    generated = re.search(r"(\d+) states generated", output)
    distinct = re.search(r"(\d+) distinct states found", output)
    return {
        "status": "TLS_HANDSHAKE_MODEL_PROVED",
        "claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
        "judge": "tlc", "tlc_version": provenance["version"],
        "source_sha256": digest,
        "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest(),
        "states_generated": int(generated.group(1)) if generated else None,
        "distinct_states": int(distinct.group(1)) if distinct else None,
        "properties": ["DEADLOCK_FREE", "STATE_INITIALIZED",
                       "TERMINAL_REACHABILITY"],
        "cryptographic_strength_proved": False,
        "transcript_authenticity_proved": False,
        "mbedtls_implementation_refinement_proved": False,
    }


def write_validation(path: str | Path, evidence: dict) -> None:
    """Write canonical validation evidence after a successful real-TLC run."""
    if evidence.get("status") != "TLS_HANDSHAKE_MODEL_PROVED":
        raise ValueError("TLS_VALIDATION_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def verify_tls_handshake_evidence(artifact: dict, source: bytes,
                                  evidence: dict) -> dict:
    """Verify a published TLC envelope remains bound to source and model."""
    try:
        tla, _cfg = render_tls_handshake(artifact)
    except ValueError as exc:
        return _fail(str(exc))
    source_hash = hashlib.sha256(source).hexdigest()
    tla_hash = hashlib.sha256(tla.encode()).hexdigest()
    properties = {"DEADLOCK_FREE", "STATE_INITIALIZED", "TERMINAL_REACHABILITY"}
    valid = (
        artifact.get("source_sha256") == source_hash
        and evidence.get("source_sha256") == source_hash
        and evidence.get("generated_tla_sha256") == tla_hash
        and evidence.get("status") == "TLS_HANDSHAKE_MODEL_PROVED"
        and evidence.get("judge") == "tlc"
        and set(evidence.get("properties", [])) == properties
        and evidence.get("cryptographic_strength_proved") is False
        and evidence.get("transcript_authenticity_proved") is False
        and evidence.get("mbedtls_implementation_refinement_proved") is False)
    if not valid:
        return _fail("TLS_EVIDENCE_BINDING_MISMATCH")
    return {"status": "TLS_HANDSHAKE_EVIDENCE_BOUND",
            "claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
            "source_sha256": source_hash, "generated_tla_sha256": tla_hash,
            "tlc_version": evidence.get("tlc_version"),
            "distinct_states": evidence.get("distinct_states"),
            "states_generated": evidence.get("states_generated")}
