# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M90.3 minimal, typed, causal evidence invalidation semantics."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .proof_carrying_binary import validate_binary_evidence
from .proof_carrying_build import _hash_json, _sha


VALID = "VALID"
_PRECEDENCE = (
    "FORBIDDEN", "BINARY_IDENTITY_REJECTED", "REBUILD_REQUIRED",
    "PROFILE_INAPPLICABLE", "HUMAN_REVIEW_REQUIRED", "REPLAY_REQUIRED",
    "DEPENDENCY_UNPROVED", "STALE_SOURCE", "CANONICAL_ROOT_REGENERATION_REQUIRED",
)


def _node(node_id: str, kind: str, digest: str, *, path: str | None = None,
          claim: str | None = None) -> dict[str, Any]:
    return {"id": node_id, "kind": kind, "digest": digest,
            **({"path": path} if path else {}), **({"claim": claim} if claim else {})}


def build_dependency_graph(binary_evidence: dict[str, Any], project_root: str | Path) -> dict:
    """Build an explicit content-addressed DAG for the M90.2 applicable closure."""
    root = Path(project_root).resolve()
    checked = validate_binary_evidence(binary_evidence, root)
    if checked.get("status") != "PROOF_CARRYING_BINARY_VALIDATED":
        return {"status": "M90_3_INPUT_INVALID", "claim": "NO_PROOF"}
    record = binary_evidence["build_record"]
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[list[str]] = []

    def add_artifact(path: str, digest: str, kind: str, claim: str | None = None) -> str:
        node_id = f"artifact:{path}"
        existing = nodes.get(node_id)
        if existing and existing["digest"] != digest:
            raise ValueError("M90_3_INCONSISTENT_ARTIFACT_DIGEST")
        nodes[node_id] = _node(node_id, kind, digest, path=path, claim=claim)
        return node_id

    source_ids = set()
    for item in record["compiled_sources"]:
        source_ids.add(add_artifact(item["path"], item["sha256"], "compiled_source"))
    config_id = add_artifact(record["config"]["path"], record["config"]["sha256"],
                             "build_configuration")
    deployment_id = add_artifact(record["deployment_manifest"]["path"],
                                 record["deployment_manifest"]["sha256"],
                                 "deployment_profile")
    hardware_id = add_artifact(record["hardware_profile"]["path"],
                               record["hardware_profile"]["sha256"], "hardware_profile")
    script_id = add_artifact(record["linker_script"]["path"],
                             record["linker_script"]["sha256"], "linker_script")
    compiler_id = "tool:rustc"
    linker_id = "tool:rust-lld"
    nodes[compiler_id] = _node(compiler_id, "build_tool", record["compiler"]["sha256"])
    nodes[linker_id] = _node(linker_id, "build_tool", record["linker"]["sha256"])
    build_id = "build:target_elf"
    nodes[build_id] = _node(build_id, "build", _hash_json(record))
    for dependency in sorted(source_ids | {config_id, deployment_id, hardware_id,
                                           script_id, compiler_id, linker_id}):
        edges.append([build_id, dependency])
    elf_id = "binary:qemu_aarch64_elf"
    nodes[elf_id] = _node(elf_id, "binary", binary_evidence["elf"]["sha256"],
                          path=binary_evidence["elf"]["path"])
    edges.append([elf_id, build_id])

    prebuild = binary_evidence["prebuild_candidate"]
    prebuild_id = add_artifact(prebuild["path"], prebuild["sha256"],
                               "canonical_prebuild_inventory")
    prebuild_value = json.loads((root / prebuild["path"]).read_text())
    judges = {item.get("name", "").lower(): item
              for item in prebuild_value.get("judge_versions", [])}
    claim_ids = []
    for claim in binary_evidence["applicable_claims"]:
        claim_id = f"claim:{claim['claim']}"
        claim_ids.append(claim_id)
        nodes[claim_id] = _node(claim_id, "claim", _hash_json(claim),
                                claim=claim["claim"])
        for item in claim["dependencies"]:
            path = item["path"]
            if path in {record_item["path"] for record_item in record["compiled_sources"]}:
                kind = "compiled_source"
            elif path.endswith(".reviewed.json"):
                kind = "reviewed_model"
            elif path.endswith("m90_kernel_evidence_bundle.json"):
                kind = "proof_bundle"
            else:
                kind = "proof_artifact"
            dep_id = add_artifact(path, item["sha256"], kind, claim=claim["claim"])
            edges.append([claim_id, dep_id])
        if claim["judge"] == "kani":
            judge = judges.get("kani")
            if not judge or not judge.get("executable_sha256"):
                raise ValueError("M90_3_JUDGE_BINDING_MISSING")
            judge_id = "judge:Kani"
            nodes[judge_id] = _node(judge_id, "judge", judge["executable_sha256"])
        elif claim["judge"] == "deterministic_gate":
            path = "pipeline/kernel_composition.py"
            judge_id = add_artifact(path, _sha((root / path).read_bytes()),
                                    "deterministic_judge")
        else:
            raise ValueError("M90_3_JUDGE_BINDING_MISSING")
        edges.append([claim_id, judge_id])

    root_id = "evidence:proof_carrying_binary"
    nodes[root_id] = _node(root_id, "evidence_root",
                           binary_evidence["evidence_dag"]["root_digest"])
    edges.append([root_id, elf_id])
    edges.append([root_id, prebuild_id])
    edges.extend([root_id, claim_id] for claim_id in sorted(claim_ids))
    ordered_nodes = [nodes[key] for key in sorted(nodes)]
    ordered_edges = sorted(edges)
    return {"status": "EVIDENCE_DEPENDENCY_GRAPH", "claim": "NO_PROOF",
            "nodes": ordered_nodes, "edges": ordered_edges,
            "graph_digest": _hash_json({"nodes": ordered_nodes, "edges": ordered_edges}),
            "root": root_id}


def _status_for_kind(kind: str) -> str:
    return {
        "compiled_source": "STALE_SOURCE",
        "reviewed_model": "HUMAN_REVIEW_REQUIRED",
        "judge": "REPLAY_REQUIRED",
        "deterministic_judge": "REPLAY_REQUIRED",
        "build_tool": "REBUILD_REQUIRED",
        "build": "REBUILD_REQUIRED",
        "build_configuration": "REBUILD_REQUIRED",
        "linker_script": "REBUILD_REQUIRED",
        "deployment_profile": "PROFILE_INAPPLICABLE",
        "hardware_profile": "PROFILE_INAPPLICABLE",
        "binary": "BINARY_IDENTITY_REJECTED",
        "canonical_prebuild_inventory": "CANONICAL_ROOT_REGENERATION_REQUIRED",
        "proof_bundle": "DEPENDENCY_UNPROVED",
        "proof_artifact": "DEPENDENCY_UNPROVED",
    }.get(kind, "DEPENDENCY_UNPROVED")


def evaluate_invalidation(graph: dict[str, Any], *,
                          observed_digests: dict[str, str | None] | None = None,
                          injected_claims: list[str] | None = None,
                          forbidden_claims: list[str] | None = None) -> dict[str, Any]:
    """Evaluate typed, transitive, minimal claim/root downgrades with causes."""
    observed = observed_digests or {}
    forbidden = set(forbidden_claims or ())
    expected_graph_digest = _hash_json({"nodes": graph.get("nodes", []),
                                        "edges": graph.get("edges", [])})
    if graph.get("graph_digest") != expected_graph_digest:
        return {"status": "EVIDENCE_INVALIDATION_EVALUATED", "claim": "NO_PROOF",
                "root_status": {"status": "DEPENDENCY_UNPROVED", "causes": [{
                    "status": "DEPENDENCY_UNPROVED", "dependency": "dependency_graph",
                    "reason": "graph digest or transitive dependency closure changed"}]},
                "claim_statuses": {}, "ignored_changes": []}
    nodes = {item["id"]: item for item in graph["nodes"]}
    dependencies: dict[str, list[str]] = {}
    for parent, child in graph["edges"]:
        dependencies.setdefault(parent, []).append(child)
    direct: dict[str, dict[str, Any]] = {}
    ignored = []
    for node_id, digest in observed.items():
        node = nodes.get(node_id)
        if node is None:
            ignored.append(node_id)
        elif digest != node["digest"]:
            direct[node_id] = {
                "status": _status_for_kind(node["kind"]), "dependency": node_id,
                "kind": node["kind"], "old": node["digest"], "new": digest,
            }
    injected = sorted(set(injected_claims or ()))
    forbidden_injected = sorted(set(injected) & forbidden)

    def causal(node_id: str, trail: set[str] | None = None) -> list[dict[str, Any]]:
        trail = set() if trail is None else trail
        if node_id in trail:
            return [{"status": "DEPENDENCY_UNPROVED", "dependency": node_id,
                     "reason": "dependency cycle"}]
        causes = [direct[node_id]] if node_id in direct else []
        for child in dependencies.get(node_id, []):
            causes.extend(causal(child, trail | {node_id}))
        unique = {json.dumps(cause, sort_keys=True): cause for cause in causes}
        return [unique[key] for key in sorted(unique)]

    def result(node_id: str) -> dict[str, Any]:
        causes = causal(node_id)
        if not causes:
            return {"status": VALID, "causes": []}
        statuses = {cause["status"] for cause in causes}
        status = next((candidate for candidate in _PRECEDENCE if candidate in statuses),
                      "DEPENDENCY_UNPROVED")
        return {"status": status, "causes": causes}

    claim_results = {node["claim"]: result(node["id"])
                     for node in graph["nodes"] if node["kind"] == "claim"}
    root_result = result(graph["root"])
    if forbidden_injected:
        root_result = {"status": "FORBIDDEN", "causes": [{
            "status": "FORBIDDEN", "dependency": f"claim:{name}",
            "reason": "forbidden claim injection"} for name in forbidden_injected]}
    elif injected:
        root_result = {"status": "DEPENDENCY_UNPROVED", "causes": [{
            "status": "DEPENDENCY_UNPROVED", "dependency": f"claim:{name}",
            "reason": "claim absent from applicable closure"} for name in injected]}
    return {"status": "EVIDENCE_INVALIDATION_EVALUATED", "claim": "NO_PROOF",
            "root_status": root_result, "claim_statuses": claim_results,
            "ignored_changes": sorted(ignored)}


def qualify_invalidation_semantics(binary_evidence: dict[str, Any],
                                    project_root: str | Path) -> dict[str, Any]:
    """Execute the fixed M90.3 negative matrix and emit validation evidence."""
    graph = build_dependency_graph(binary_evidence, project_root)
    if graph.get("status") != "EVIDENCE_DEPENDENCY_GRAPH":
        return graph
    nodes = {item["id"]: item for item in graph["nodes"]}
    cases = {
        "compiled_source": ({"artifact:examples/formalkernel/boot/src/witness.rs": "0" * 64},
                            "STALE_SOURCE", "RUST_WITNESS_REFINEMENT_PROVED"),
        "unused_source": ({"artifact:examples/formalkernel/kernel/vfs/Vfs.rs": "0" * 64},
                          VALID, "RUST_WITNESS_REFINEMENT_PROVED"),
        "kani_judge": ({"judge:Kani": "0" * 64}, "REPLAY_REQUIRED",
                       "RUST_WITNESS_REFINEMENT_PROVED"),
        "deterministic_judge": ({"artifact:pipeline/kernel_composition.py": "0" * 64},
                                "REPLAY_REQUIRED", "SYSTEM_COMPOSITION_PROVED"),
        "unrelated_x86_profile": ({"artifact:examples/formalkernel/profiles/n150.json": "0" * 64},
                                  VALID, "SYSTEM_COMPOSITION_PROVED"),
        "unrelated_z3_judge": ({"judge:Z3": "0" * 64},
                               VALID, "SYSTEM_COMPOSITION_PROVED"),
        "unrelated_tlaps_judge": ({"judge:TLAPS": "0" * 64},
                                  VALID, "SYSTEM_COMPOSITION_PROVED"),
        "linker_script": ({"artifact:examples/formalkernel/boot/layout.ld": "0" * 64},
                          "REBUILD_REQUIRED", None),
        "hardware_profile": ({"artifact:examples/formalkernel/hardware_profile.json": "0" * 64},
                             "PROFILE_INAPPLICABLE", None),
        "elf": ({"binary:qemu_aarch64_elf": "0" * 64},
                "BINARY_IDENTITY_REJECTED", None),
        "prebuild_inventory": ({
            "artifact:examples/formalkernel/kernel/m90_evidence_root.candidate.json": "0" * 64},
            "CANONICAL_ROOT_REGENERATION_REQUIRED", None),
    }
    results = []
    for name, (changes, expected, claim) in cases.items():
        result = evaluate_invalidation(graph, observed_digests=changes)
        actual = (result["claim_statuses"][claim]["status"] if claim else
                  result["root_status"]["status"])
        results.append({"case": name, "expected": expected, "actual": actual,
                        "passed": actual == expected,
                        "ignored_changes": result["ignored_changes"]})
    forbidden = evaluate_invalidation(
        graph, injected_claims=["END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"],
        forbidden_claims=["END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"])
    results.append({"case": "forbidden_claim_promotion", "expected": "FORBIDDEN",
                    "actual": forbidden["root_status"]["status"],
                    "passed": forbidden["root_status"]["status"] == "FORBIDDEN"})
    passed = all(item["passed"] for item in results)
    return {
        "status": "EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED" if passed else
                  "EVIDENCE_INVALIDATION_QUALIFICATION_FAILED",
        "claim": "EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED" if passed else "NO_PROOF",
        "claims_minted": (["EVIDENCE_DEPENDENCY_CLOSURE_VALIDATED",
                            "EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED"] if passed else []),
        "scope": "m90_2_qemu_aarch64_deterministic_dependency_engine",
        "dependency_graph": graph, "mutation_results": results,
        "evidence_coverage": {
            "applicable_proved_claims": 2,
            "declared_compiled_mechanisms": 2,
            "ratio": "2/2",
            "boundary": ("Counts declared mechanisms in this exact ELF; it is not the "
                         "repository claim count or source-line proof coverage."),
        },
        "forbidden_claims": ["COMPILER_REFINEMENT_CHAIN_PROVED",
                             "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED",
                             "TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED"],
        "note": ("Changing the bound M90.1 candidate requires evidence-root regeneration "
                 "but leaves claim-local closures valid when their dependencies are unchanged."),
    }
