# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M90.4 empirical target-binary and evidence-root reproducibility."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .evidence_invalidation import build_dependency_graph, evaluate_invalidation
from .proof_carrying_binary import _elf_identity, _resolve_tool, _version
from .proof_carrying_build import _canonical_hash, _hash_json, _sha, ArtifactBinding


_SOURCE_PATHS = (
    "examples/formalkernel/boot/src/boot_order.rs",
    "examples/formalkernel/boot/src/main.rs",
    "examples/formalkernel/boot/src/witness.rs",
)
_LINKER_PATH = "examples/formalkernel/boot/layout.ld"


def _fail(status: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "claim": "NO_PROOF", **extra}


def _stage(root: Path, destination: Path, *, timestamp: int | None = None) -> None:
    for relative in (*_SOURCE_PATHS, _LINKER_PATH):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, target)
        if timestamp is not None:
            os.utime(target, (timestamp, timestamp))


def _compile(root: Path, stage: Path, config: dict[str, Any], *,
             environment: dict[str, str], extra_flags: list[str] | None = None) -> dict:
    rustc, linker = _resolve_tool("rustc"), _resolve_tool("rust-lld")
    if rustc is None or linker is None:
        return _fail("M90_REPRO_BUILD_TOOL_UNAVAILABLE")
    output = stage / "formalkernel.elf"
    flags = [flag.replace("{PROJECT_ROOT}", str(stage)) for flag in config["rustc_flags"]]
    flags.extend(extra_flags or ())
    invocation = [str(rustc), "--edition", "2021", "--target", config["target"],
                  "--crate-type", "bin", f"-Clinker={linker}",
                  f"-Clink-arg=-T{stage / _LINKER_PATH}", *flags,
                  "-o", str(output), str(stage / config["crate_root"])]
    run = subprocess.run(invocation, cwd=stage, env=environment, capture_output=True,
                         text=True, timeout=180, check=False)
    if run.returncode != 0:
        return _fail("M90_REPRO_BUILD_FAILED", exit_code=run.returncode,
                     stderr=run.stderr[-500:], stdout=run.stdout[-500:])
    raw = output.read_bytes()
    identity = _elf_identity(raw)
    return {
        "status": "CLEAN_BUILD_OBSERVED", "raw_elf_sha256": _sha(raw),
        "elf_size": len(raw), "elf_structural_digest": _hash_json(identity),
        "identity": identity,
        "compiler_sha256": _sha(rustc.read_bytes()),
        "compiler_version": _version([str(rustc), "-Vv"]),
        "linker_sha256": _sha(linker.read_bytes()),
        "linker_version": _version([str(linker), "-flavor", "gnu", "--version"]),
    }


def _canonical_root(root: Path, config: dict[str, Any], build: dict[str, Any],
                    binary_evidence: dict[str, Any], source_order: list[str] | None = None) -> str:
    ordered = source_order or list(_SOURCE_PATHS)
    bindings = [ArtifactBinding(path=path, sha256=_sha((root / path).read_bytes()))
                for path in ordered]
    # _canonical_hash sorts by path, so manifest enumeration order is not semantic.
    value = {
        "target": config["target"], "rustc_flags": config["rustc_flags"],
        "codegen_environment": config["codegen_environment"],
        "source_closure_hash": _canonical_hash(bindings),
        "compiler_sha256": build["compiler_sha256"],
        "linker_sha256": build["linker_sha256"],
        "linker_script_sha256": _sha((root / _LINKER_PATH).read_bytes()),
        "raw_elf_sha256": build["raw_elf_sha256"],
        "elf_structural_digest": build["elf_structural_digest"],
        "applicable_claim_closure_hash": binary_evidence[
            "applicable_claim_closure_hash"],
        "prebuild_candidate_sha256": binary_evidence["prebuild_candidate"]["sha256"],
    }
    return _hash_json(value)


def observe_reproducibility(project_root: str | Path, config_path: str | Path,
                            binary_evidence_path: str | Path) -> dict[str, Any]:
    """Run two independent clean builds plus declared nondeterminism probes."""
    root = Path(project_root).resolve()
    try:
        config = json.loads(Path(config_path).read_text())
        binary = json.loads(Path(binary_evidence_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return _fail("M90_REPRO_INPUT_INVALID", message=str(exc))
    if config.get("codegen_environment") != {} or binary.get("claim") != \
            "PROOF_CARRYING_BINARY_VALIDATED":
        return _fail("M90_REPRO_INPUT_INVALID")
    with tempfile.TemporaryDirectory(prefix="m90-repro-a-", dir="/tmp") as first_dir, \
            tempfile.TemporaryDirectory(prefix="m90-repro-b-", dir="/tmp") as second_dir, \
            tempfile.TemporaryDirectory(prefix="m90-repro-time-", dir="/tmp") as time_dir, \
            tempfile.TemporaryDirectory(prefix="m90-repro-env-", dir="/tmp") as env_dir, \
            tempfile.TemporaryDirectory(prefix="m90-repro-buildid-", dir="/tmp") as buildid_dir:
        stages = [Path(first_dir), Path(second_dir), Path(time_dir), Path(env_dir),
                  Path(buildid_dir)]
        _stage(root, stages[0], timestamp=1_600_000_000)
        _stage(root, stages[1], timestamp=1_700_000_000)
        _stage(root, stages[2], timestamp=1_800_000_000)
        _stage(root, stages[3], timestamp=1_900_000_000)
        _stage(root, stages[4], timestamp=2_000_000_000)
        first = _compile(root, stages[0], config, environment={})
        second = _compile(root, stages[1], config, environment={})
        timestamp = _compile(root, stages[2], config, environment={})
        env_build = _compile(root, stages[3], config, environment={
            "LC_ALL": "C", "TZ": "Pacific/Auckland", "SOURCE_DATE_EPOCH": "123456789"})
        build_id = _compile(root, stages[4], config, environment={},
                            extra_flags=["-Clink-arg=--build-id=sha1"])
    builds = [first, second, timestamp, env_build, build_id]
    if any(item.get("status") != "CLEAN_BUILD_OBSERVED" for item in builds):
        return _fail("M90_REPRO_BUILD_FAILED", builds=builds)
    first_root = _canonical_root(root, config, first, binary)
    second_root = _canonical_root(root, config, second, binary)
    reordered_root = _canonical_root(root, config, second, binary,
                                     source_order=list(reversed(_SOURCE_PATHS)))
    graph = build_dependency_graph(binary, root)
    build_drift = evaluate_invalidation(
        graph, observed_digests={"build:target_elf": "0" * 64})
    compiler_drift = evaluate_invalidation(
        graph, observed_digests={"tool:rustc": "0" * 64})
    cases = [
        {"case": "independent_build_directory", "expected": first["raw_elf_sha256"],
         "actual": second["raw_elf_sha256"],
         "passed": first["raw_elf_sha256"] == second["raw_elf_sha256"]},
        {"case": "file_timestamp_change", "expected": first["raw_elf_sha256"],
         "actual": timestamp["raw_elf_sha256"],
         "passed": first["raw_elf_sha256"] == timestamp["raw_elf_sha256"]},
        {"case": "locale_timezone_source_date_epoch_injection",
         "expected_artifact": first["raw_elf_sha256"], "actual_artifact": env_build["raw_elf_sha256"],
         "artifact_equal": first["raw_elf_sha256"] == env_build["raw_elf_sha256"],
         "expected_evidence_status": "REBUILD_REQUIRED",
         "actual_evidence_status": build_drift["root_status"]["status"],
         "passed": build_drift["root_status"]["status"] == "REBUILD_REQUIRED"},
        {"case": "source_manifest_order", "expected": first_root,
         "actual": reordered_root, "passed": first_root == reordered_root},
        {"case": "compiler_identity_change", "expected": "REBUILD_REQUIRED",
         "actual": compiler_drift["root_status"]["status"],
         "passed": compiler_drift["root_status"]["status"] == "REBUILD_REQUIRED"},
        {"case": "deliberate_build_id_perturbation",
         "expected": "RAW_ELF_DIFFERENT", "actual": (
             "RAW_ELF_DIFFERENT" if first["raw_elf_sha256"] != build_id["raw_elf_sha256"]
             else "RAW_ELF_EQUAL"),
         "structural_digest_equal": first["elf_structural_digest"] ==
                                     build_id["elf_structural_digest"],
         "passed": first["raw_elf_sha256"] != build_id["raw_elf_sha256"]},
        {"case": "linker_input_ordering",
         "status": "NOT_APPLICABLE_SINGLE_RUST_CRATE_NO_EXTERNAL_LINK_INPUT_LIST",
         "passed": True},
    ]
    binary_equal = first["raw_elf_sha256"] == second["raw_elf_sha256"]
    structural_equal = first["elf_structural_digest"] == second["elf_structural_digest"]
    roots_equal = first_root == second_root
    passed = binary_equal and structural_equal and roots_equal and all(
        item["passed"] for item in cases)
    return {
        "status": "REPRODUCIBLE_BUILD_OBSERVATION_COMPLETE" if passed else
                  "REPRODUCIBLE_BUILD_OBSERVATION_FAILED",
        "claim": "REPRODUCIBLE_BINARY_BUILD_OBSERVED" if passed else "NO_PROOF",
        "claims_minted": (["REPRODUCIBLE_BINARY_BUILD_OBSERVED",
                            "REPRODUCIBLE_EVIDENCE_ROOT_OBSERVED"] if passed else []),
        "scope": "two_independent_qemu_aarch64_clean_builds",
        "observations": [
            {"label": "clean_build_a", **first},
            {"label": "clean_build_b", **second},
        ],
        "raw_elf_reproducible": binary_equal,
        "structural_digest_reproducible": structural_equal,
        "canonical_evidence_root_reproducible": roots_equal,
        "canonical_evidence_root": first_root if roots_equal else None,
        "mutation_results": cases,
        "build_inputs": {
            "config_sha256": _sha(Path(config_path).read_bytes()),
            "binary_evidence_sha256": _sha(Path(binary_evidence_path).read_bytes()),
            "source_closure": list(_SOURCE_PATHS),
            "linker_script": _LINKER_PATH, "codegen_environment": {},
        },
        "normalization": {
            "elf_bytes": "NONE",
            "structural_identity": "PARSED_WITHOUT_NORMALIZATION",
            "canonical_evidence_root": ("Excludes temporary output-directory spelling; "
                                        "retains raw ELF and structural digests."),
        },
        "forbidden_claims": ["REPRODUCIBLE_BUILD_PROVED",
                             "COMPILER_REFINEMENT_CHAIN_PROVED",
                             "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"],
    }
