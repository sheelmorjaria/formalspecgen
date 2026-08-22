# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M77 symbolic dynamic VM quota and NUMA ownership-accounting gate."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "DYNAMIC_VM_PROOF_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _sum(items: list[str]) -> str:
    return "(+ " + " ".join(items) + ")"


def verify_dynamic_vm(path: str | Path) -> dict:
    artifact_path = Path(path)
    try:
        raw = artifact_path.read_bytes()
        artifact = json.loads(raw)
        processes = artifact["processes"]
        nodes = artifact["numa_nodes"]
        quotas = artifact["process_quotas_pages"]
        capacities = artifact["node_capacities_pages"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("DYNAMIC_VM_ARTIFACT_INVALID", str(exc))
    if not (isinstance(processes, list) and len(processes) == 3 and
            isinstance(nodes, list) and len(nodes) == 2 and
            set(quotas) == set(processes) and set(capacities) == set(nodes)):
        return _fail("DYNAMIC_VM_TOPOLOGY_INVALID")
    values = list(quotas.values()) + list(capacities.values())
    if not all(isinstance(value, int) and not isinstance(value, bool) and value > 0
               for value in values):
        return _fail("DYNAMIC_VM_BOUND_INVALID")
    admitted = artifact.get("admitted_memory_pages")
    physical = artifact.get("physical_pages")
    if not isinstance(admitted, int) or admitted <= 0 or admitted > physical or \
            admitted > sum(capacities.values()):
        return _fail("DYNAMIC_VM_ADMISSION_INVALID")
    if artifact.get("operations") != ["alloc", "free", "map",
                                       "fork_reserve_cow", "exec_release"]:
        return _fail("DYNAMIC_VM_OPERATION_SET_INVALID")
    if artifact.get("quota_exhaustion") != "QuotaExhausted_and_stutter" or \
            artifact.get("global_exhaustion") != \
            "AdmittedMemoryExhausted_and_stutter" or \
            artifact.get("node_exhaustion") != "NodeExhausted_and_stutter":
        return _fail("DYNAMIC_VM_BACKPRESSURE_INVALID")
    ceilings = ("hardware_tlb_coherence_proved",
                "hardware_page_table_walker_proved",
                "arbitrary_process_count_proved", "numa_hotplug_proved",
                "allocator_implementation_refinement_proved")
    if any(artifact.get(name) is not False for name in ceilings):
        return _fail("DYNAMIC_VM_EPISTEMIC_BOUNDARY_INVALID")

    cells = {(p, n): f"x_{p}_{n}" for p in processes for n in nodes}
    post = {(p, n): f"y_{p}_{n}" for p in processes for n in nodes}
    pre_process = {p: _sum([cells[p, n] for n in nodes]) for p in processes}
    pre_node = {n: _sum([cells[p, n] for p in processes]) for n in nodes}
    post_process = {p: _sum([post[p, n] for n in nodes]) for p in processes}
    post_node = {n: _sum([post[p, n] for p in processes]) for n in nodes}
    pre_total, post_total = _sum(list(cells.values())), _sum(list(post.values()))

    def invariant(cell_map, proc_sums, node_sums, total):
        clauses = [f"(>= {name} 0)" for name in cell_map.values()]
        clauses += [f"(<= {proc_sums[p]} {quotas[p]})" for p in processes]
        clauses += [f"(<= {node_sums[n]} {capacities[n]})" for n in nodes]
        clauses += [f"(<= {total} {admitted})"]
        return "(and " + " ".join(clauses) + ")"

    pre_inv = invariant(cells, pre_process, pre_node, pre_total)
    post_inv = invariant(post, post_process, post_node, post_total)
    transitions = []

    def relation(updates: dict[tuple[str, str], str]):
        return "(and " + " ".join(
            f"(= {post[key]} {updates.get(key, cells[key])})" for key in cells) + ")"

    for p in processes:
        for n in nodes:
            guard = (f"(and (< {pre_process[p]} {quotas[p]}) "
                     f"(< {pre_total} {admitted}) "
                     f"(< {pre_node[n]} {capacities[n]}))")
            transitions.append(f"(and {guard} {relation({(p, n): f'(+ {cells[p, n]} 1)'})})")
            transitions.append(f"(and (not {guard}) {relation({})})")
            free_guard = f"(> {cells[p, n]} 0)"
            transitions.append(f"(and {free_guard} {relation({(p, n): f'(- {cells[p, n]} 1)'})})")
            transitions.append(f"(and (not {free_guard}) {relation({})})")
        transitions.append(relation({(p, n): "0" for n in nodes}))
    transitions.append(relation({}))  # map: accounting stutters
    for parent in processes:
        for child in processes:
            if parent == child:
                continue
            node_guards = " ".join(
                f"(<= (+ {pre_node[n]} {cells[parent, n]}) {capacities[n]})"
                for n in nodes)
            guard = (f"(and (= {pre_process[child]} 0) "
                     f"(<= {pre_process[parent]} {quotas[child]}) "
                     f"(<= (+ {pre_total} {pre_process[parent]}) {admitted}) "
                     f"{node_guards})")
            updates = {(child, n): cells[parent, n] for n in nodes}
            transitions.append(f"(and {guard} {relation(updates)})")
            transitions.append(f"(and (not {guard}) {relation({})})")
    smt = ["(set-logic QF_LIA)"]
    for name in list(cells.values()) + list(post.values()):
        smt.append(f"(declare-const {name} Int)")
    smt += [f"(assert {pre_inv})",
            f"(assert (or {' '.join(transitions)}))",
            f"(assert (not {post_inv}))", "(check-sat)"]
    encoding = "\n".join(smt) + "\n"
    z3 = shutil.which("z3")
    if z3 is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "z3_unavailable", "judge_pending": "z3"}
    try:
        run = subprocess.run([z3, "-in"], input=encoding, capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _fail("DYNAMIC_VM_Z3_FAILED", str(exc))
    if run.returncode != 0 or run.stdout.strip() != "unsat":
        return _fail("DYNAMIC_VM_INVARIANT_COUNTEREXAMPLE",
                     run.stdout + run.stderr)
    return {
        "status": "VM_RESOURCE_ISOLATION_PROVED",
        "claims": ["VM_RESOURCE_ISOLATION_PROVED", "NUMA_ACCOUNTING_PROVED"],
        "judge": "z3", "scope": "three_process_two_node_symbolic_accounting",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "smt_sha256": hashlib.sha256(encoding.encode()).hexdigest(),
        "process_count": len(processes), "numa_node_count": len(nodes),
        "admitted_memory_pages": admitted, "physical_pages": physical,
        "operations_proved_inductive": artifact["operations"],
        "deterministic_exhaustion": True,
        **{name: False for name in ceilings},
    }
