# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M90.2 exact target-ELF identity and applicable-evidence binding."""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from .proof_carrying_build import (
    ArtifactBinding,
    _binding,
    _canonical_hash,
    _hash_json,
    _sha,
    validate_evidence_root_candidate,
)


CLAIM = "PROOF_CARRYING_BINARY_VALIDATED"
SCOPE = "qemu_aarch64_elf_artifact_identity_and_applicable_evidence_closure"
LOCKED = (
    "COMPILER_REFINEMENT_CHAIN_PROVED",
    "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED",
    "TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED",
)

# These rules are deliberately code-owned. A build descriptor selects mechanisms,
# not claims; adding a claim requires an explicit applicability rule and tests.
_APPLICABILITY = {
    "boot_composition": {
        "claim": "SYSTEM_COMPOSITION_PROVED",
        "required_sources": (
            "examples/formalkernel/boot/src/main.rs",
            "examples/formalkernel/boot/src/boot_order.rs",
        ),
        "artifacts": ("examples/formalkernel/kernel/composition.json",),
    },
    "bounded_queue_witness": {
        "claim": "RUST_WITNESS_REFINEMENT_PROVED",
        "required_sources": (
            "examples/formalkernel/boot/src/main.rs",
            "examples/formalkernel/boot/src/witness.rs",
        ),
        "artifacts": (
            "examples/formalkernel/boot/proofs/Cargo.toml",
            "examples/formalkernel/boot/proofs/src/lib.rs",
        ),
    },
}


def _fail(status: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "claim": "NO_PROOF", **extra}


def _resolve_tool(name: str) -> Path | None:
    resolved = shutil.which(name)
    if resolved:
        if name == "rustc":
            probe = subprocess.run([resolved, "--print", "sysroot"],
                                   capture_output=True, text=True, timeout=10,
                                   check=False)
            direct = Path(probe.stdout.strip()) / "bin/rustc"
            if probe.returncode == 0 and direct.is_file():
                return direct.absolute()
        # Preserve argv[0] for rustup proxy symlinks: resolving ``rustc`` to the
        # rustup executable changes dispatch semantics.
        return Path(resolved).absolute()
    if name == "rust-lld":
        candidates = sorted((Path.home() / ".rustup/toolchains").glob(
            "stable-*/lib/rustlib/*/bin/rust-lld"))
        if candidates:
            return candidates[-1].resolve()
    return None


def _version(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True,
                            timeout=10, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return (result.stdout or result.stderr).strip()


def _read_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    required = {
        "target", "deployment_manifest", "hardware_profile", "linker_script",
        "crate_root", "compiled_sources", "enabled_mechanisms", "rustc_flags",
        "codegen_environment",
    }
    if set(value) != required or value["target"] != "aarch64-unknown-none-softfloat":
        raise ValueError("M90_BUILD_INPUT_UNBOUND")
    if value["codegen_environment"] != {}:
        raise ValueError("M90_BUILD_INPUT_UNBOUND")
    if sorted(value["enabled_mechanisms"]) != sorted(_APPLICABILITY):
        raise ValueError("M90_APPLICABILITY_UNDECLARED")
    return value


def _validate_profiles(root: Path, config: dict[str, Any]) -> None:
    deployment = json.loads((root / config["deployment_manifest"]).read_text())
    hardware = json.loads((root / config["hardware_profile"]).read_text())
    if deployment.get("deployment") != "microkernel" or \
            hardware.get("target") != "formalkernel-demo":
        raise ValueError("M90_BUILD_PROFILE_MISMATCH")


def _source_bindings(root: Path, config: dict[str, Any]) -> list[ArtifactBinding]:
    declared = sorted(config["compiled_sources"])
    expected = sorted({path for rule in _APPLICABILITY.values()
                       for path in rule["required_sources"]})
    if declared != expected:
        raise ValueError("M90_BUILD_SOURCE_CLOSURE_INVALID")
    return [_binding(root / path, root) for path in declared]


def _elf_identity(raw: bytes) -> dict[str, Any]:
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise ValueError("M90_ELF_INVALID")
    if raw[4] != 2 or raw[5] != 1:
        raise ValueError("M90_ELF_TARGET_MISMATCH")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw, 0)
    (_, elf_type, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = header
    if elf_type != 2 or machine != 183 or version != 1:
        raise ValueError("M90_ELF_TARGET_MISMATCH")
    if phentsize != 56 or shentsize != 64:
        raise ValueError("M90_ELF_LAYOUT_UNSUPPORTED")
    if phoff + phnum * phentsize > len(raw) or shoff + shnum * shentsize > len(raw):
        raise ValueError("M90_ELF_TRUNCATED")
    programs = []
    for index in range(phnum):
        values = struct.unpack_from("<IIQQQQQQ", raw, phoff + index * phentsize)
        programs.append(dict(zip(
            ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align"),
            values)))
    sections_raw = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + i * shentsize)
                    for i in range(shnum)]
    if shstrndx >= shnum:
        raise ValueError("M90_ELF_STRING_TABLE_INVALID")
    string_section = sections_raw[shstrndx]
    start, size = string_section[4], string_section[5]
    if start + size > len(raw):
        raise ValueError("M90_ELF_STRING_TABLE_INVALID")
    strings = raw[start:start + size]

    def section_name(offset: int) -> str:
        if offset >= len(strings):
            raise ValueError("M90_ELF_STRING_TABLE_INVALID")
        end = strings.find(b"\0", offset)
        if end < 0:
            raise ValueError("M90_ELF_STRING_TABLE_INVALID")
        return strings[offset:end].decode("ascii")

    sections = []
    for values in sections_raw:
        sections.append({
            "name": section_name(values[0]), "type": values[1], "flags": values[2],
            "address": values[3], "offset": values[4], "size": values[5],
            "link": values[6], "info": values[7], "alignment": values[8],
            "entry_size": values[9],
        })
    return {
        "elf_class": "ELF64", "endian": "little", "machine": "AArch64",
        "machine_id": machine, "elf_type": "EXEC", "entry_point": entry,
        "header_flags": flags, "header_size": ehsize, "program_headers": programs,
        "sections": sections, "build_id": None,
    }


def _claim_closure(root: Path, config: dict[str, Any], bundle_path: Path,
                   source_paths: set[str]) -> list[dict[str, Any]]:
    bundle = json.loads(bundle_path.read_text())
    if bundle.get("status") != "KERNEL_EVIDENCE_BUNDLE" or \
            bundle.get("deployment") != "microkernel":
        raise ValueError("M90_EVIDENCE_BUNDLE_INVALID")
    by_claim: dict[str, list[dict[str, Any]]] = {}
    for item in bundle.get("claims", []):
        by_claim.setdefault(item.get("claim", ""), []).append(item)
    closure = []
    for mechanism in sorted(config["enabled_mechanisms"]):
        rule = _APPLICABILITY[mechanism]
        if not set(rule["required_sources"]).issubset(source_paths):
            raise ValueError("M90_APPLICABLE_CLAIM_SOURCE_MISSING")
        matches = [item for item in by_claim.get(rule["claim"], [])
                   if item.get("profile") is None]
        if len(matches) != 1:
            raise ValueError("M90_APPLICABLE_CLAIM_MISSING")
        dependencies = [_binding(bundle_path, root)]
        dependencies += [_binding(root / path, root) for path in rule["artifacts"]]
        dependencies += [_binding(root / path, root) for path in rule["required_sources"]]
        closure.append({
            "claim": rule["claim"], "scope": matches[0]["scope"],
            "judge": matches[0]["judge"], "mechanism": mechanism,
            "dependencies": [item.model_dump(mode="json") for item in
                             sorted(dependencies, key=lambda item: item.path)],
        })
    return closure


def _dag(build_record: dict[str, Any], elf: dict[str, Any], closure: list[dict[str, Any]],
         prebuild: ArtifactBinding) -> dict[str, Any]:
    nodes = {
        "prebuild_candidate": prebuild.sha256,
        "build_record": _hash_json(build_record),
        "elf": elf["sha256"],
        "elf_structure": elf["structural_digest"],
        "applicable_claim_closure": _hash_json(closure),
    }
    edges = [
        ["build_record", "prebuild_candidate"], ["elf", "build_record"],
        ["elf_structure", "elf"], ["applicable_claim_closure", "elf"],
    ]
    return {"nodes": nodes, "edges": edges,
            "root_digest": _hash_json({"nodes": nodes, "edges": edges})}


def _invocation(root: Path, config: dict[str, Any], rustc: Path, linker: Path,
                output_elf: Path) -> list[str]:
    flags = [flag.replace("{PROJECT_ROOT}", str(root))
             for flag in config["rustc_flags"]]
    return [str(rustc), "--edition", "2021", "--target", config["target"],
            "--crate-type", "bin", f"-Clinker={linker}",
            f"-Clink-arg=-T{root / config['linker_script']}", *flags,
            "-o", str(output_elf), str(root / config["crate_root"])]


def build_binary_evidence(project_root: str | Path, config_path: str | Path,
                          prebuild_path: str | Path, bundle_path: str | Path,
                          output_elf: str | Path) -> dict[str, Any]:
    """Build the exact ELF, recompute applicability, and return M90.2 evidence."""
    root = Path(project_root).resolve()
    config_path, prebuild_path, bundle_path = (Path(p).resolve() for p in
                                               (config_path, prebuild_path, bundle_path))
    output_elf = Path(output_elf).resolve()
    try:
        config = _read_config(config_path)
        _validate_profiles(root, config)
        prebuild = json.loads(prebuild_path.read_text())
        precheck = validate_evidence_root_candidate(prebuild, root)
        if precheck.get("status") != "EVIDENCE_ROOT_CANDIDATE_VALIDATED":
            return _fail("M90_PREBUILD_CANDIDATE_INVALID")
        sources = _source_bindings(root, config)
        rustc, linker = _resolve_tool("rustc"), _resolve_tool("rust-lld")
        if rustc is None or linker is None:
            return _fail("M90_BUILD_TOOL_UNAVAILABLE")
        linker_script = root / config["linker_script"]
        crate_root = root / config["crate_root"]
        invocation = _invocation(root, config, rustc, linker, output_elf)
        output_elf.parent.mkdir(parents=True, exist_ok=True)
        run = subprocess.run(invocation, cwd=root, env={},
                             capture_output=True, text=True, timeout=180, check=False)
        if run.returncode != 0:
            return _fail("M90_TARGET_ELF_BUILD_FAILED", exit_code=run.returncode,
                         stderr=run.stderr[-500:], stdout=run.stdout[-500:])
        build_record = {
            "target": config["target"], "deployment": "microkernel",
            "deployment_manifest": _binding(root / config["deployment_manifest"], root).model_dump(),
            "hardware_profile": _binding(root / config["hardware_profile"], root).model_dump(),
            "config": _binding(config_path, root).model_dump(),
            "compiled_sources": [item.model_dump() for item in sources],
            "source_closure_hash": _canonical_hash(sources),
            "compiler": {"path": str(rustc), "sha256": _sha(rustc.read_bytes()),
                         "version": _version([str(rustc), "-Vv"])},
            "linker": {"path": str(linker), "sha256": _sha(linker.read_bytes()),
                       "version": _version([str(linker), "-flavor", "gnu", "--version"])},
            "linker_script": _binding(linker_script, root).model_dump(),
            "invocation": invocation, "codegen_environment": {},
        }
        raw = output_elf.read_bytes()
        identity = _elf_identity(raw)
        structural_digest = _hash_json(identity)
        elf = {"path": output_elf.relative_to(root).as_posix(), "sha256": _sha(raw),
               "size": len(raw), "identity": identity,
               "structural_digest": structural_digest}
        closure = _claim_closure(root, config, bundle_path,
                                 {item.path for item in sources})
        prebinding = _binding(prebuild_path, root)
        dag = _dag(build_record, elf, closure, prebinding)
        return {
            "schema_version": 1, "lane": "M90.2_target_elf_evidence_binding",
            "status": CLAIM, "claim": CLAIM, "scope": SCOPE,
            "prebuild_candidate": prebinding.model_dump(),
            "build_record": build_record, "elf": elf,
            "applicable_claims": closure,
            "applicable_claim_closure_hash": _hash_json(closure),
            "evidence_dag": dag,
            "trusted_assumptions": [
                "rustc and rust-lld are identity-bound but are not verified compilers",
                "the claim binds evidence applicability and artifact identity, not ELF semantics",
                "physical QEMU or silicon execution is outside this claim",
            ],
            "locked_claims": list(LOCKED),
            "forbidden_claims": list(LOCKED),
            "release_seal_status": "HUMAN_SEAL_PENDING",
        }
    except (OSError, ValueError, KeyError, json.JSONDecodeError,
            subprocess.TimeoutExpired, RuntimeError) as exc:
        return _fail(str(exc) if str(exc).startswith("M90_") else
                     "M90_BUILD_INPUT_UNBOUND", message=str(exc))


def validate_binary_evidence(value: dict[str, Any], project_root: str | Path) -> dict[str, Any]:
    """Replay hashes, structural ELF identity, applicability, and the evidence DAG."""
    root = Path(project_root).resolve()
    required = {"schema_version", "lane", "status", "claim", "scope",
                "prebuild_candidate", "build_record", "elf", "applicable_claims",
                "applicable_claim_closure_hash", "evidence_dag", "trusted_assumptions",
                "locked_claims", "forbidden_claims", "release_seal_status"}
    if set(value) != required or value.get("status") != CLAIM or value.get("claim") != CLAIM:
        return _fail("M90_BINARY_EVIDENCE_SCHEMA_INVALID")
    try:
        pre = ArtifactBinding.model_validate(value["prebuild_candidate"])
        pre_path = root / pre.path
        if not pre_path.is_file() or _sha(pre_path.read_bytes()) != pre.sha256:
            return _fail("M90_PREBUILD_CANDIDATE_STALE")
        if validate_evidence_root_candidate(json.loads(pre_path.read_text()), root).get(
                "status") != "EVIDENCE_ROOT_CANDIDATE_VALIDATED":
            return _fail("M90_PREBUILD_CANDIDATE_INVALID")
        record = value["build_record"]
        bindings = [ArtifactBinding.model_validate(record[key]) for key in
                    ("deployment_manifest", "hardware_profile", "config", "linker_script")]
        bindings += [ArtifactBinding.model_validate(item) for item in record["compiled_sources"]]
        bindings += [ArtifactBinding.model_validate(item) for claim in value["applicable_claims"]
                     for item in claim["dependencies"]]
        for item in bindings:
            path = root / item.path
            if not path.is_file() or _sha(path.read_bytes()) != item.sha256:
                return _fail("M90_BINARY_DEPENDENCY_STALE", path=item.path)
        sources = [ArtifactBinding.model_validate(item) for item in record["compiled_sources"]]
        if _canonical_hash(sources) != record["source_closure_hash"]:
            return _fail("M90_BUILD_SOURCE_CLOSURE_INVALID")
        for tool in (record["compiler"], record["linker"]):
            path = Path(tool["path"])
            if not path.is_file() or _sha(path.read_bytes()) != tool["sha256"]:
                return _fail("M90_BUILD_TOOL_REPLAY_REQUIRED")
        elf_path = root / value["elf"]["path"]
        raw = elf_path.read_bytes()
        if _sha(raw) != value["elf"]["sha256"] or len(raw) != value["elf"]["size"]:
            return _fail("M90_ELF_IDENTITY_MISMATCH")
        identity = _elf_identity(raw)
        if identity != value["elf"]["identity"] or _hash_json(identity) != value["elf"][
                "structural_digest"]:
            return _fail("M90_ELF_STRUCTURE_MISMATCH")
        config = _read_config(root / record["config"]["path"])
        _validate_profiles(root, config)
        if record["deployment_manifest"] != _binding(
                root / config["deployment_manifest"], root).model_dump() or \
                record["hardware_profile"] != _binding(
                    root / config["hardware_profile"], root).model_dump():
            return _fail("M90_BUILD_PROFILE_MISMATCH")
        expected_invocation = _invocation(
            root, config, Path(record["compiler"]["path"]),
            Path(record["linker"]["path"]), root / value["elf"]["path"])
        if record["invocation"] != expected_invocation or record["codegen_environment"] != {}:
            return _fail("M90_BUILD_PROVENANCE_MISMATCH")
        derived = _claim_closure(root, config,
                                 root / "examples/formalkernel/kernel/m90_kernel_evidence_bundle.json",
                                 {item.path for item in sources})
        if derived != value["applicable_claims"]:
            return _fail("M90_APPLICABILITY_CLOSURE_MISMATCH")
        if _hash_json(derived) != value["applicable_claim_closure_hash"]:
            return _fail("M90_APPLICABILITY_CLOSURE_STALE")
        if any(item["claim"] in value["forbidden_claims"] for item in derived):
            return _fail("M90_FORBIDDEN_CLAIM")
        expected_dag = _dag(record, value["elf"], derived, pre)
        if expected_dag != value["evidence_dag"]:
            return _fail("M90_EVIDENCE_DAG_STALE")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return _fail("M90_BINARY_EVIDENCE_INVALID", message=str(exc))
    return {"status": CLAIM, "claim": CLAIM, "scope": SCOPE,
            "elf_sha256": value["elf"]["sha256"],
            "applicable_claims": len(value["applicable_claims"])}
