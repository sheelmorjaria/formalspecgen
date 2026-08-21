# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M63: bounded per-task scheduler liveness under declared fairness."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import config
from .domain_v2_tools import (get_tlc_provenance, require_tlc_provenance,
                              run_tlc_artifacts)


def _fail(code: str, message: str = "") -> dict:
    return {"status": "SCHEDULER_LIVENESS_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def render_scheduler_liveness(module: str, task_count: int) -> tuple[str, str]:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module):
        raise ValueError("SCHEDULER_MODULE_INVALID")
    if not isinstance(task_count, int) or not 1 <= task_count <= 8:
        raise ValueError("SCHEDULER_TASK_BOUND_INVALID")
    last = task_count - 1
    tla = f"""---- MODULE {module} ----
EXTENDS Naturals, FiniteSets
CONSTANT TaskCount
ASSUME TaskCount = {task_count}
Tasks == 0..(TaskCount - 1)
NoneTask == TaskCount
VARIABLES ready, cursor, running
vars == <<ready, cursor, running>>

Init == /\\ ready = {{}}
        /\\ cursor = 0
        /\\ running = NoneTask

Wake(i) == /\\ i \\in Tasks /\\ i \\notin ready
           /\\ ready' = ready \\cup {{i}}
           /\\ running' = NoneTask
           /\\ UNCHANGED cursor

Block(i) == /\\ i \\in ready
            /\\ ready' = ready \\ {{i}}
            /\\ running' = NoneTask
            /\\ UNCHANGED cursor

NextReady == CHOOSE i \\in Tasks:
  /\\ i \\in ready
  /\\ \\A j \\in ready:
       ((i + TaskCount - cursor) % TaskCount) <=
       ((j + TaskCount - cursor) % TaskCount)

Schedule == /\\ ready # {{}}
            /\\ running' = NextReady
            /\\ cursor' = (NextReady + 1) % TaskCount
            /\\ UNCHANGED ready

Environment == \\/ \\E i \\in Tasks: Wake(i)
               \\/ \\E i \\in Tasks: Block(i)
Next == Environment \\/ Schedule
Spec == Init /\\ [][Next]_vars /\\ WF_vars(Schedule)

TypeOK == /\\ ready \\subseteq Tasks
          /\\ cursor \\in Tasks
          /\\ running \\in Tasks \\/ running = NoneTask
ScheduledWasReady == running \\in Tasks => running \\in ready
TaskProgress(i) == (i \\in ready) ~> (running = i \\/ i \\notin ready)
StarvationFreedom == \\A i \\in Tasks: TaskProgress(i)
====
"""
    cfg = (f"CONSTANT TaskCount = {task_count}\n"
           "SPECIFICATION Spec\nINVARIANT TypeOK\n"
           "INVARIANT ScheduledWasReady\nPROPERTY StarvationFreedom\n")
    return tla, cfg


def _source_hash(artifact: dict, root: Path) -> tuple[Path, str]:
    source = artifact.get("source")
    expected = artifact.get("source_sha256")
    if not isinstance(source, str) or not isinstance(expected, str):
        raise ValueError("SCHEDULER_SOURCE_BINDING_INVALID")
    path = (root / source).resolve()
    if root.resolve() not in path.parents or not path.is_file():
        raise ValueError("SCHEDULER_SOURCE_PATH_INVALID")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise ValueError("SCHEDULER_SOURCE_HASH_MISMATCH")
    return path, digest


def validate_scheduler_liveness(artifact: dict, root: str | Path) -> dict:
    try:
        if artifact.get("policy") != "bounded_round_robin":
            raise ValueError("SCHEDULER_POLICY_UNSUPPORTED")
        _path, source_hash = _source_hash(artifact, Path(root))
        tla, cfg = render_scheduler_liveness(
            artifact.get("module", ""), artifact.get("task_count"))
        provenance = require_tlc_provenance(get_tlc_provenance(
            config.TLC_JAR, java=config.JAVA_BIN))
        result = run_tlc_artifacts(tla, cfg, module_name=artifact["module"],
                                   tlc_jar=config.TLC_JAR,
                                   java=config.JAVA_BIN,
                                   timeout=config.TLC_TIMEOUT)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    if result.get("status") != "VERIFIED":
        return _fail("SCHEDULER_TLC_FAILED", result.get("output", ""))
    output = result.get("output", "")
    distinct = re.search(r"(\d+) distinct states found", output)
    return {
        "status": "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED",
        "claim": "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED",
        "judge": "tlc", "tlc_version": provenance["version"],
        "source_sha256": source_hash,
        "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest(),
        "task_count": artifact["task_count"],
        "policy": artifact["policy"],
        "distinct_states": int(distinct.group(1)) if distinct else None,
        "fairness": "WF_vars(Schedule)",
        "property": "per-task ready leads-to scheduled-or-blocked",
        "unbounded_task_liveness_proved": False,
        "hardware_timer_fairness_proved": False,
        "source_model_refinement_proved": False,
    }


def write_scheduler_validation(path: str | Path, evidence: dict) -> None:
    if evidence.get("status") != "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED":
        raise ValueError("SCHEDULER_VALIDATION_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def verify_scheduler_liveness_evidence(artifact: dict, root: str | Path,
                                       evidence: dict) -> dict:
    try:
        if artifact.get("policy") != "bounded_round_robin":
            raise ValueError("SCHEDULER_POLICY_UNSUPPORTED")
        _path, source_hash = _source_hash(artifact, Path(root))
        tla, _ = render_scheduler_liveness(
            artifact.get("module", ""), artifact.get("task_count"))
    except (OSError, TypeError, ValueError) as exc:
        return _fail(str(exc))
    valid = (evidence.get("status") ==
             "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED"
             and evidence.get("judge") == "tlc"
             and evidence.get("source_sha256") == source_hash
             and evidence.get("generated_tla_sha256") ==
             hashlib.sha256(tla.encode()).hexdigest()
             and evidence.get("task_count") == artifact.get("task_count")
             and evidence.get("policy") == artifact.get("policy")
             and evidence.get("fairness") == "WF_vars(Schedule)"
             and evidence.get("property") ==
             "per-task ready leads-to scheduled-or-blocked"
             and evidence.get("unbounded_task_liveness_proved") is False
             and evidence.get("hardware_timer_fairness_proved") is False
             and evidence.get("source_model_refinement_proved") is False)
    if not valid:
        return _fail("SCHEDULER_LIVENESS_EVIDENCE_BINDING_MISMATCH")
    return {"status": "SCHEDULER_LIVENESS_EVIDENCE_BOUND",
            "claim": "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED",
            "source_sha256": source_hash,
            "generated_tla_sha256": evidence["generated_tla_sha256"],
            "task_count": evidence["task_count"],
            "policy": evidence["policy"],
            "distinct_states": evidence.get("distinct_states"),
            "fairness": evidence["fairness"]}
