# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M90 canonical proof-carrying-build manifest generation and validation."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .capability_registry import milestone_capabilities
from .doctor import inspect_environment


class ArtifactBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    sha256: str


class ClaimEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: str
    scope: str
    judge: str
    subsystem: str | None = None
    profile: str | None = None
    dependencies: list[ArtifactBinding]


class EvidenceRootManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    lane: Literal["M90.1_canonical_evidence_manifest"]
    status: Literal["EVIDENCE_ROOT_CANDIDATE"]
    claim: Literal["NO_PROOF"]
    binary_status: Literal["BINARY_BUILD_PENDING"]
    binary_sha256: str | None = None
    source_tree_hash: str
    source_files: list[ArtifactBinding]
    deployment_profile: ArtifactBinding
    hardware_profiles: list[ArtifactBinding]
    evidence_bundle: ArtifactBinding
    claim_entries: list[ClaimEntry]
    claim_graph_hash: str
    judge_versions: list[dict[str, Any]]
    judge_manifest_hash: str
    compiler_toolchain: dict[str, str | None]
    trusted_assumptions: list[str]
    judge_pending: list[str]
    forbidden_claims: list[str]
    local_tool_patches: list[dict[str, Any]]
    human_promotions: list[ArtifactBinding]
    promotion_inventory_hash: str
    locked_claims: list[str]


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _binding(path: Path, root: Path) -> ArtifactBinding:
    return ArtifactBinding(path=path.resolve().relative_to(root).as_posix(),
                           sha256=_sha(path.read_bytes()))


def _canonical_hash(bindings: list[ArtifactBinding]) -> str:
    payload = [{"path": item.path, "sha256": item.sha256}
               for item in sorted(bindings, key=lambda item: item.path)]
    return _sha(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _hash_json(value: Any) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _production_sources(root: Path) -> list[ArtifactBinding]:
    bases = (
        "examples/formalkernel/boot/src",
        "examples/formalkernel/driver",
        "examples/formalkernel/kernel/ipc",
        "examples/formalkernel/kernel/loader",
        "examples/formalkernel/kernel/net",
        "examples/formalkernel/kernel/scheduler",
        "examples/formalkernel/kernel/user",
        "examples/formalkernel/kernel/vfs",
        "examples/formalkernel/unikernel/src",
    )
    suffixes = {".rs", ".c", ".h", ".S", ".ld"}
    paths = sorted(path for base in bases for path in (root / base).rglob("*")
                   if path.is_file() and path.suffix in suffixes)
    return [_binding(path, root) for path in paths]


def _validation_scopes(root: Path) -> dict[str, str]:
    scopes: dict[str, str] = {}
    for path in sorted((root / "examples/formalkernel/kernel").rglob("*.validation.json")):
        try:
            value = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        claims = [value.get("claim"), *value.get("claims_minted", [])]
        for claim in claims:
            if isinstance(claim, str) and claim != "NO_PROOF" and value.get("scope"):
                scopes[claim] = value["scope"]
    return scopes


def _registry_index(root: Path, deployment: str) -> tuple[dict[str, tuple], list[str], list[str], list[str]]:
    index: dict[str, tuple] = {}
    assumptions: set[str] = set()
    pending: set[str] = set()
    forbidden: set[str] = set()
    for item in milestone_capabilities():
        milestone = item.milestone
        assert milestone is not None
        # M90.1 is the immutable pre-build inventory. Later M90 results depend
        # on it and must never flow backwards into their own prerequisite.
        lane_prefix = milestone.lane.split("_", 1)[0]
        after_frozen_m90 = (lane_prefix.startswith("M") and lane_prefix[1:].isdigit()
                            and int(lane_prefix[1:]) > 90)
        if milestone.lane.startswith(("M90_2_", "M90_3_", "M90_4_", "M90_5_")) \
                or after_frozen_m90:
            continue
        if deployment not in milestone.deployment_profiles:
            continue
        assumptions.update(milestone.assumptions)
        forbidden.update(milestone.claims_forbidden)
        pending.update(stage.claim for stage in milestone.claims
                       if stage.claim not in milestone.completed_claims)
        bindings = []
        for relative in milestone.artifact_hash_bindings:
            path = root / relative
            if path.is_file():
                bindings.append(_binding(path, root))
        for claim in milestone.completed_claims:
            index[claim] = (milestone.lane, tuple(bindings))
    return index, sorted(assumptions), sorted(pending), sorted(forbidden)


def _resolve_source(root: Path, source: str | None) -> list[ArtifactBinding]:
    if not source:
        return []
    matches = sorted((root / "examples/formalkernel").rglob(Path(source).name))
    return [_binding(path, root) for path in matches if path.is_file()]


def _toolchain(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=10, check=False)
    except OSError:
        return None
    output = (result.stdout or result.stderr).strip()
    return output if result.returncode == 0 else None


def build_evidence_root_candidate(
        project_root: str | Path, bundle_path: str | Path,
        deployment_manifest: str | Path, hardware_profiles: list[str | Path],
        *, environment_report: dict[str, Any] | None = None) -> dict:
    """Build a canonical non-claiming M90.1 manifest from exact evidence bytes."""
    root = Path(project_root).resolve()
    bundle_path = Path(bundle_path).resolve()
    manifest_path = Path(deployment_manifest).resolve()
    profile_paths = [Path(path).resolve() for path in hardware_profiles]
    try:
        bundle = json.loads(bundle_path.read_text())
        deployment = json.loads(manifest_path.read_text())["deployment"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        return {"status": "EVIDENCE_ROOT_INPUT_INVALID", "claim": "NO_PROOF",
                "message": str(exc)}
    if bundle.get("status") != "KERNEL_EVIDENCE_BUNDLE" or \
            bundle.get("deployment") != deployment:
        return {"status": "EVIDENCE_ROOT_INPUT_INVALID", "claim": "NO_PROOF"}
    base_dependencies = [_binding(manifest_path, root)] + [
        _binding(path, root) for path in profile_paths]
    registry, assumptions, pending, forbidden = _registry_index(root, deployment)
    scopes = _validation_scopes(root)
    entries = []
    seen = set()
    for raw_claim in bundle.get("claims", []):
        name = raw_claim.get("claim")
        if not isinstance(name, str):
            return {"status": "EVIDENCE_ROOT_CLAIM_INVALID", "claim": "NO_PROOF"}
        lane, registry_bindings = registry.get(name, (None, ()))
        dependencies = {item.path: item for item in (
            base_dependencies + list(registry_bindings) +
            _resolve_source(root, raw_claim.get("source")))}
        entries.append(ClaimEntry(
            claim=name, scope=raw_claim.get("scope") or scopes.get(name) or
            f"registry_lane:{lane or 'unmapped'}",
            judge=raw_claim.get("judge") or "none",
            subsystem=raw_claim.get("subsystem"), profile=raw_claim.get("profile"),
            dependencies=sorted(dependencies.values(), key=lambda item: item.path)))
        seen.add(name)
    for name, (lane, registry_bindings) in sorted(registry.items()):
        if name in seen:
            continue
        dependencies = {item.path: item for item in
                        (base_dependencies + list(registry_bindings))}
        entries.append(ClaimEntry(
            claim=name, scope=scopes.get(name, f"registry_lane:{lane}"),
            judge="registry_bound_evidence",
            subsystem=lane,
            dependencies=sorted(dependencies.values(), key=lambda item: item.path)))
    entries.sort(key=lambda item: (item.claim, item.scope, item.profile or ""))

    report = environment_report or inspect_environment()
    judges = [{key: item.get(key) for key in (
        "name", "status", "version", "resolved_executable", "executable_sha256",
        "invocation_environment") if key in item}
        for item in report.get("capabilities", [])]
    patch_ledger = root / "examples/formalkernel/kernel/refinement/refinedrust_boundary_ledger.json"
    patches = []
    if patch_ledger.is_file():
        ledger = json.loads(patch_ledger.read_text())
        patches = [{**item, "ledger_path": patch_ledger.relative_to(root).as_posix(),
                    "ledger_sha256": _sha(patch_ledger.read_bytes())}
                   for item in ledger.get("boundaries", []) if item.get("patch_sha256")]
    reviewed = sorted((root / "examples/formalkernel/kernel").glob("*.reviewed.json"))
    promotions = [_binding(path, root) for path in reviewed]
    sources = _production_sources(root)
    model = EvidenceRootManifest(
        lane="M90.1_canonical_evidence_manifest",
        status="EVIDENCE_ROOT_CANDIDATE", claim="NO_PROOF",
        binary_status="BINARY_BUILD_PENDING", binary_sha256=None,
        source_tree_hash=_canonical_hash(sources), source_files=sources,
        deployment_profile=_binding(manifest_path, root),
        hardware_profiles=[_binding(path, root) for path in profile_paths],
        evidence_bundle=_binding(bundle_path, root) if bundle_path.is_relative_to(root)
        else ArtifactBinding(path=str(bundle_path), sha256=_sha(bundle_path.read_bytes())),
        claim_entries=entries,
        claim_graph_hash=_hash_json([item.model_dump(mode="json") for item in entries]),
        judge_versions=judges, judge_manifest_hash=_hash_json(judges),
        compiler_toolchain={"rustc": _toolchain(["rustc", "-Vv"]),
                            "cc": _toolchain(["gcc", "--version"]),
                            "linker": _toolchain(["ld", "--version"])},
        trusted_assumptions=assumptions,
        judge_pending=pending, forbidden_claims=forbidden,
        local_tool_patches=patches, human_promotions=promotions,
        promotion_inventory_hash=_canonical_hash(promotions),
        locked_claims=["PROOF_CARRYING_BINARY_VALIDATED",
                       "COMPILER_REFINEMENT_CHAIN_PROVED",
                       "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"])
    return model.model_dump(mode="json")


def validate_evidence_root_candidate(value: dict, project_root: str | Path) -> dict:
    """Validate canonical structure and every available dependency hash."""
    root = Path(project_root).resolve()
    try:
        model = EvidenceRootManifest.model_validate(value)
    except Exception as exc:  # Pydantic supplies structured validation details.
        return {"status": "EVIDENCE_ROOT_SCHEMA_INVALID", "claim": "NO_PROOF",
                "message": str(exc)}
    bindings = [*model.source_files, model.deployment_profile,
                *model.hardware_profiles, model.evidence_bundle,
                *model.human_promotions]
    bindings.extend(dep for entry in model.claim_entries for dep in entry.dependencies)
    for item in bindings:
        path = root / item.path
        if not path.is_file() or _sha(path.read_bytes()) != item.sha256:
            return {"status": "EVIDENCE_ROOT_DEPENDENCY_STALE", "claim": "NO_PROOF",
                    "path": item.path}
    if _canonical_hash(model.source_files) != model.source_tree_hash:
        return {"status": "EVIDENCE_ROOT_SOURCE_TREE_STALE", "claim": "NO_PROOF"}
    if _hash_json([item.model_dump(mode="json") for item in model.claim_entries]) != \
            model.claim_graph_hash:
        return {"status": "EVIDENCE_ROOT_CLAIM_GRAPH_STALE", "claim": "NO_PROOF"}
    if _hash_json(model.judge_versions) != model.judge_manifest_hash:
        return {"status": "EVIDENCE_ROOT_JUDGE_MANIFEST_STALE", "claim": "NO_PROOF"}
    if _canonical_hash(model.human_promotions) != model.promotion_inventory_hash:
        return {"status": "EVIDENCE_ROOT_PROMOTION_INVENTORY_STALE", "claim": "NO_PROOF"}
    for patch in model.local_tool_patches:
        ledger = root / str(patch.get("ledger_path", ""))
        if not ledger.is_file() or _sha(ledger.read_bytes()) != patch.get("ledger_sha256"):
            return {"status": "EVIDENCE_ROOT_LOCAL_PATCH_STALE", "claim": "NO_PROOF"}
    for judge in model.judge_versions:
        executable = judge.get("resolved_executable")
        digest = judge.get("executable_sha256")
        if executable and digest and (not Path(executable).is_file()
                                      or _sha(Path(executable).read_bytes()) != digest):
            return {"status": "EVIDENCE_ROOT_JUDGE_REPLAY_REQUIRED",
                    "claim": "NO_PROOF", "judge": judge.get("name")}
    if any(entry.claim in model.forbidden_claims for entry in model.claim_entries):
        return {"status": "EVIDENCE_ROOT_FORBIDDEN_CLAIM", "claim": "NO_PROOF"}
    if model.binary_sha256 is not None or model.binary_status != "BINARY_BUILD_PENDING":
        return {"status": "EVIDENCE_ROOT_BINARY_BOUNDARY_INVALID", "claim": "NO_PROOF"}
    return {"status": "EVIDENCE_ROOT_CANDIDATE_VALIDATED", "claim": "NO_PROOF",
            "claim_entries": len(model.claim_entries),
            "source_files": len(model.source_files)}
