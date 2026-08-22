# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M90.5 human-only exact-hash deployment evidence sealing."""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

from .evidence_invalidation import (
    build_dependency_graph,
    evaluate_invalidation,
    qualify_invalidation_semantics,
)
from .proof_carrying_binary import validate_binary_evidence
from .proof_carrying_build import _hash_json, _sha
from .reproducible_build import observe_reproducibility


_RELEASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_UNACCEPTABLE = {
    "STALE_SOURCE", "REPLAY_REQUIRED", "REBUILD_REQUIRED",
    "HUMAN_REVIEW_REQUIRED", "DEPENDENCY_UNPROVED",
    "BINARY_IDENTITY_REJECTED", "CANONICAL_ROOT_REGENERATION_REQUIRED",
    "FORBIDDEN",
}


def _fail(code: str, **extra: Any) -> dict[str, Any]:
    return {"status": "DEPLOYMENT_EVIDENCE_SEAL_REFUSED", "claim": "NO_PROOF",
            "code": code, **extra}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _seal_payload(root: Path, release: str, timestamp: str, binary: dict[str, Any],
                  reproducibility: dict[str, Any], invalidation: dict[str, Any],
                  allowed_pending: list[str]) -> dict[str, Any]:
    prebuild = _load(root / binary["prebuild_candidate"]["path"])
    bundle = _load(root / "examples/formalkernel/kernel/m90_kernel_evidence_bundle.json")
    applicable = [item["claim"] for item in binary["applicable_claims"]]
    all_bundle_claims = [item.get("claim") for item in bundle.get("claims", [])]
    not_applicable = sorted([item for item in all_bundle_claims if item not in applicable])
    graph = invalidation["dependency_graph"]
    judge_nodes = [item for item in graph["nodes"] if item["kind"] in
                   {"judge", "deterministic_judge"}]
    payload = {
        "schema_version": 1,
        "status": "SEALED_DEPLOYMENT_EVIDENCE",
        "claim": "NO_PROOF",
        "release_identity": release,
        "release_timestamp": timestamp,
        "binary": {
            "path": binary["elf"]["path"],
            "elf_sha256": binary["elf"]["sha256"],
            "elf_size": binary["elf"]["size"],
            "elf_structural_digest": binary["elf"]["structural_digest"],
            "entry_point": binary["elf"]["identity"]["entry_point"],
        },
        "canonical_evidence_root_sha256": reproducibility["canonical_evidence_root"],
        "deployment": {
            "target": binary["build_record"]["target"],
            "profile": binary["build_record"]["deployment"],
            "hardware_scope": "formalkernel-demo",
            "deployment_manifest": binary["build_record"]["deployment_manifest"],
            "hardware_profile": binary["build_record"]["hardware_profile"],
        },
        "applicable_claims": applicable,
        "empirical_observations": reproducibility["claims_minted"],
        "evidence_operations": invalidation["claims_minted"],
        "residuals": {
            "applicable_pending": [],
            "allowed_pending": sorted(allowed_pending),
            "assumptions": binary["trusted_assumptions"],
            "forbidden_claims": sorted(set(binary["forbidden_claims"]) |
                                       set(invalidation["forbidden_claims"]) |
                                       set(reproducibility["forbidden_claims"])),
            "not_applicable_bundle_claims": not_applicable,
            "repository_judge_pending_inventory": prebuild["judge_pending"],
            "repository_assumption_inventory": prebuild["trusted_assumptions"],
        },
        "provenance": {
            "build": binary["build_record"],
            "applicable_claim_closure_hash": binary["applicable_claim_closure_hash"],
            "dependency_graph_digest": graph["graph_digest"],
            "judge_nodes": judge_nodes,
            "reviewed_promotions": prebuild["human_promotions"],
            "local_verifier_patches": prebuild["local_tool_patches"],
            "binary_evidence_sha256": _sha((root / "examples/formalkernel/kernel/m90_binary_evidence.json").read_bytes()),
            "invalidation_evidence_sha256": _sha((root / "examples/formalkernel/kernel/m90_invalidation.validation.json").read_bytes()),
            "reproducibility_evidence_sha256": _sha((root / "examples/formalkernel/kernel/m90_reproducibility.validation.json").read_bytes()),
        },
        "approval": {
            "method": "human_explicit_hash_acceptance",
            "accepted_elf_sha256": binary["elf"]["sha256"],
            "accepted_evidence_root_sha256": reproducibility["canonical_evidence_root"],
            "private_key_signature": None,
            "note": "Content seal only; hardware-backed signing and attestation are deferred.",
        },
    }
    payload["seal_sha256"] = _hash_json(payload)
    return payload


def seal_deployment_evidence(
        project_root: str | Path, *, accept_elf_sha256: str,
        accept_evidence_root_sha256: str, release: str,
        allowed_pending: list[str] | None = None,
        output_path: str | Path | None = None,
        release_timestamp: str | None = None,
        binary_evidence_path: str | Path | None = None,
        invalidation_path: str | Path | None = None,
        reproducibility_path: str | Path | None = None) -> dict[str, Any]:
    """Perform the human-only exact-hash acceptance and write a content seal."""
    root = Path(project_root).resolve()
    if not _RELEASE_RE.fullmatch(release):
        return _fail("M90_RELEASE_ID_INVALID")
    binary_path = Path(binary_evidence_path or
                       root / "examples/formalkernel/kernel/m90_binary_evidence.json").resolve()
    invalidation_file = Path(invalidation_path or
                             root / "examples/formalkernel/kernel/m90_invalidation.validation.json").resolve()
    reproducibility_file = Path(reproducibility_path or
                                root / "examples/formalkernel/kernel/m90_reproducibility.validation.json").resolve()
    try:
        binary, invalidation, reproducibility = map(
            _load, (binary_path, invalidation_file, reproducibility_file))
    except (OSError, json.JSONDecodeError) as exc:
        return _fail("M90_SEAL_INPUT_INVALID", message=str(exc))
    if accept_elf_sha256 != binary.get("elf", {}).get("sha256"):
        return _fail("M90_SEAL_ELF_HASH_NOT_ACCEPTED")
    if accept_evidence_root_sha256 != reproducibility.get("canonical_evidence_root"):
        return _fail("M90_SEAL_EVIDENCE_ROOT_NOT_ACCEPTED")
    validated = validate_binary_evidence(binary, root)
    if validated.get("status") != "PROOF_CARRYING_BINARY_VALIDATED":
        return _fail("M90_SEAL_BINARY_EVIDENCE_INVALID", cause=validated)
    fresh_invalidation = qualify_invalidation_semantics(binary, root)
    if fresh_invalidation != invalidation:
        return _fail("M90_SEAL_INVALIDATION_EVIDENCE_STALE")
    fresh_reproducibility = observe_reproducibility(
        root, root / "examples/formalkernel/kernel/m90_build_config.json", binary_path)
    if fresh_reproducibility != reproducibility:
        return _fail("M90_SEAL_REPRODUCIBILITY_EVIDENCE_STALE")
    lattice = evaluate_invalidation(build_dependency_graph(binary, root))
    statuses = [lattice["root_status"]["status"]] + [
        item["status"] for item in lattice["claim_statuses"].values()]
    bad = sorted(set(statuses) & _UNACCEPTABLE)
    if bad or any(status != "VALID" for status in statuses):
        return _fail("M90_SEAL_LATTICE_NOT_ACCEPTABLE", states=bad or statuses)
    applicable_pending: list[str] = []
    if sorted(allowed_pending or []) != applicable_pending:
        return _fail("M90_SEAL_PENDING_POLICY_MISMATCH",
                     applicable_pending=applicable_pending,
                     supplied_allowed_pending=sorted(allowed_pending or []))
    timestamp = release_timestamp or dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return _fail("M90_RELEASE_TIMESTAMP_INVALID")
    payload = _seal_payload(root, release, timestamp, binary, reproducibility,
                            invalidation, allowed_pending or [])
    output = Path(output_path or root / "examples/formalkernel/releases" /
                  f"{release}.sealed.json").resolve()
    if output.exists():
        return _fail("M90_RELEASE_ALREADY_SEALED", path=str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n")
    return {**payload, "sealed_artifact": str(output)}


def validate_deployment_seal(value: dict[str, Any], project_root: str | Path) -> dict[str, Any]:
    """Validate seal content identity and its currently bound binary/root."""
    root = Path(project_root).resolve()
    supplied = value.get("seal_sha256")
    unsigned = {key: item for key, item in value.items()
                if key not in {"seal_sha256", "sealed_artifact"}}
    if supplied != _hash_json(unsigned):
        return _fail("M90_SEAL_CONTENT_CHANGED")
    elf = root / value.get("binary", {}).get("path", "")
    if not elf.is_file() or _sha(elf.read_bytes()) != value["binary"]["elf_sha256"]:
        return _fail("M90_SEAL_ELF_STALE")
    repro = _load(root / "examples/formalkernel/kernel/m90_reproducibility.validation.json")
    if value.get("canonical_evidence_root_sha256") != repro.get("canonical_evidence_root"):
        return _fail("M90_SEAL_EVIDENCE_ROOT_STALE")
    binary = _load(root / "examples/formalkernel/kernel/m90_binary_evidence.json")
    invalidation = _load(root / "examples/formalkernel/kernel/m90_invalidation.validation.json")
    expected = _seal_payload(
        root, value["release_identity"], value["release_timestamp"], binary, repro,
        invalidation, value.get("residuals", {}).get("allowed_pending", []))
    if unsigned != {key: item for key, item in expected.items() if key != "seal_sha256"}:
        return _fail("M90_SEAL_ENVELOPE_INCOMPLETE_OR_STALE")
    return {"status": "SEALED_DEPLOYMENT_EVIDENCE", "claim": "NO_PROOF",
            "release_identity": value["release_identity"], "seal_sha256": supplied}
