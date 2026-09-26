# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed evidence for a narrow Java/JML contract-preserving refactor."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Callable

from .java_contracts import contract_surface, has_reviewed_contract, surface_differences
from .jml_io import class_name
from .verify import classify, has_dropped_vc, verify, verify_files


RefactorVerificationRunner = Callable[[str, tuple[Path, ...], str], dict]


_METHOD = re.compile(
    r"(?m)^\s*((?:public|protected)\s+(?:(?:static|final|synchronized|abstract)\s+)*"
    r"(?:<[^{;()]+>\s+)?(?:[\w.$<>\[\],?]+\s+)?[A-Za-z_$][\w$]*\s*"
    r"\([^)]*\)(?:\s+throws\s+[^{;]+)?)(?=\s*[;{])")


def _public_contract_clauses(source: str) -> list[str]:
    """Return observable JML clauses, excluding implementation proof hints.

    Class invariants and reviewed assumptions are retained. Loop invariants,
    assertions, and termination measures describe the implementation's proof
    shape and may change during a refactor.
    """
    surface = contract_surface(source, public_only=True)
    clauses = list(surface["clauses"]["class"])
    clauses.extend(clause for values in surface["clauses"]["members"].values()
                   for clause in values)
    clauses.extend(clause for values in surface["private_assumptions"].values()
                   for clause in values)
    return sorted(set(clauses))


def _surface_failure(baseline: dict, refactored: dict, *, prefix: str = "") -> dict | None:
    if baseline["parse_errors"] or refactored["parse_errors"]:
        return _fail(
            f"{prefix}unsupported_contract_syntax",
            "The Java/JML contract surface contains unsupported active syntax",
            {"baseline": baseline["parse_errors"],
             "refactored": refactored["parse_errors"]},
        )
    if not has_reviewed_contract(baseline):
        return _fail(f"{prefix}missing_trusted_contract",
                     "Baseline contains no supported JML contract statements")
    differences = surface_differences(baseline, refactored)
    differences.pop("parse_errors", None)
    api_keys = {"class", "methods", "constructors"}
    if any(key in differences for key in api_keys):
        return _fail(f"{prefix}method_surface_changed",
                     "Public/protected Java declarations differ", differences)
    if differences:
        return _fail(f"{prefix}contract_surface_changed",
                     "Method-bound public JML contracts differ", differences)
    return None


def _sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _read_text_exact(path: Path) -> str:
    """Read source without Python universal-newline translation."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def _java_fileset_trust_manifest(files: list[Path]) -> tuple[dict, dict]:
    """Return parse failures and proof-trust inputs for a Java source set."""
    errors = {}
    manifest = {}
    for path in files:
        try:
            source = _read_text_exact(path)
        except OSError as exc:
            errors[path.name] = [str(exc)]
            continue
        surface = contract_surface(source, public_only=True)
        if surface["parse_errors"]:
            errors[path.name] = surface["parse_errors"]
        proof_trust = surface.get("proof_trust", {})
        if (proof_trust.get("class") or proof_trust.get("members") or
                proof_trust.get("fields") or proof_trust.get("assumptions")):
            manifest[path.name] = proof_trust
    return errors, manifest


def public_method_surface(source: str) -> list[str]:
    """Extract a formatting-insensitive public/protected declaration surface."""
    return sorted(re.sub(r"\s+", " ", match.group(1)).strip()
                  for match in _METHOD.finditer(source))


def _verification(
        path: Path, extra_files: list[Path] | None = None, *,
        runner: RefactorVerificationRunner | None = None,
        stage: str = "verification") -> dict:
    sources = [path, *(extra_files or [])]
    if runner is not None:
        return runner(stage, tuple(sources), "java")
    check_exit, check_output = (verify(path, mode="check") if not extra_files
                                else verify_files(sources, mode="check"))
    if check_exit != 0:
        return {"status": "FAIL", "gate": "check", "tool_status": classify(check_exit),
                "output": check_output}
    esc_exit, esc_output = (verify(path, mode="esc") if not extra_files
                            else verify_files(sources, mode="esc"))
    if esc_exit != 0:
        return {"status": "FAIL", "gate": "esc", "tool_status": classify(esc_exit),
                "output": esc_output}
    if has_dropped_vc(esc_output):
        return {"status": "FAIL", "gate": "esc", "tool_status": "VACUOUS_VERIFIED",
                "output": esc_output}
    return {"status": "VERIFIED", "gate": "esc", "tool_status": "VERIFIED"}


def _polyglot_verification(
        source_file: Path, language: str, *,
        runner: RefactorVerificationRunner | None = None,
        stage: str = "verification") -> dict:
    """Re-verify one non-Java revision with its native prover (esc equivalent)."""
    if runner is not None:
        return runner(stage, (source_file,), language)
    code = _read_text_exact(source_file)
    if language == "rust":
        from .verify_rust import verify_rust
        result = verify_rust(code, mode="esc", backend="prusti")
    elif language == "c":
        from .verify_c import verify_c
        result = verify_c(code, mode="esc")
    else:  # cpp: bounded evidence, never deductive
        from .verify_cpp import verify_cpp
        result = verify_cpp(source_file)
    if result.get("status") == "VERIFIED":
        return {"status": "VERIFIED", "output": result.get("output", ""), "result": result,
                "claim": result.get("claim")}
    return {"status": result.get("status", "VERIFY_FAILED"),
            "output": result.get("output", result.get("message", "")), "result": result}


def _verify_polyglot_refactor(baseline_file: Path, refactored_file: Path,
                              language: str, *,
                              runner: RefactorVerificationRunner | None = None) -> dict:
    """Contract-preserving gate for rust (Prusti), c (Frama-C), and cpp (ESBMC)."""
    from .polyglot_surface import native_contract_surface

    baseline = _read_text_exact(baseline_file)
    refactored = _read_text_exact(refactored_file)
    baseline_surface = native_contract_surface(baseline, language)
    refactored_surface = native_contract_surface(refactored, language)
    if baseline_surface["parse_errors"] or refactored_surface["parse_errors"]:
        return _fail(
            "unsupported_contract_syntax",
            f"The {language} contract surface is incomplete or unsupported",
            {"baseline": baseline_surface["parse_errors"],
             "refactored": refactored_surface["parse_errors"]},
        )
    baseline_contracts = [
        clause for item in baseline_surface["functions"] for clause in item["contracts"]
    ] + baseline_surface["global_contracts"]
    if not baseline_contracts:
        return _fail("missing_trusted_contract",
                     f"Baseline contains no {language} contract clauses")
    baseline_api = baseline_surface["api"]
    refactored_api = refactored_surface["api"]
    if not baseline_api:
        return _fail("method_surface_changed", "Baseline exposes no public API surface")
    if not Counter(baseline_api) <= Counter(refactored_api):
        return _fail("method_surface_changed",
                     "An existing externally visible native API declaration changed")
    baseline_bindings = Counter(
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in baseline_surface["functions"])
    refactored_bindings = Counter(
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in refactored_surface["functions"])
    if not baseline_bindings <= refactored_bindings or \
            baseline_surface["global_contracts"] != refactored_surface["global_contracts"]:
        return _fail("contract_surface_changed",
                     "Existing native contracts must remain bound to their declarations")
    if baseline_surface["proof_trust"] != refactored_surface["proof_trust"]:
        return _fail(
            "proof_trust_changed",
            "Refactoring changed native trust or verification-suppression controls",
            {"baseline": baseline_surface["proof_trust"],
             "refactored": refactored_surface["proof_trust"]},
        )
    if baseline_surface.get("binding_context", []) != \
            refactored_surface.get("binding_context", []):
        return _fail(
            "binding_context_changed",
            "Refactoring changed imports or external crate bindings",
            {"baseline": baseline_surface.get("binding_context", []),
             "refactored": refactored_surface.get("binding_context", [])},
        )
    baseline_declarations = Counter(baseline_surface.get("semantic_declarations", []))
    refactored_declarations = Counter(refactored_surface.get("semantic_declarations", []))
    if not baseline_declarations <= refactored_declarations or Counter(
            baseline_surface.get("binding_declarations", [])) != Counter(
                refactored_surface.get("binding_declarations", [])):
        return _fail(
            "semantic_context_changed",
            "A native declaration that may determine contract meaning changed",
            {"baseline": baseline_surface.get("semantic_declarations", []),
             "refactored": refactored_surface.get("semantic_declarations", [])},
        )
    if baseline == refactored:
        return _fail("source_unchanged", "No refactoring change was detected")
    baseline_proof = _polyglot_verification(
        baseline_file, language, runner=runner, stage="baseline")
    if baseline_proof["status"] != "VERIFIED":
        return _fail("baseline_not_verified",
                     f"Baseline failed native {language} verification", baseline_proof)
    refactored_proof = _polyglot_verification(
        refactored_file, language, runner=runner, stage="refactored")
    if refactored_proof["status"] != "VERIFIED":
        return _fail("refactored_not_verified",
                     f"Refactored source failed native {language} verification",
                     refactored_proof)
    bounded = language == "cpp"
    return {
        "status": "VERIFIED",
        "claim": "BOUNDED_REFACTOR_CONTRACT_PRESERVED" if bounded
                 else "REFACTOR_CONTRACT_PRESERVED",
        "scope": ("bounded_declaration_bound_native_contract_check" if bounded else
                  "declaration_bound_native_contract_and_proof_trust_with_independent_proofs"),
        "language": language, "verifier": {"rust": "prusti", "c": "frama-c-wp",
                                           "cpp": "esbmc"}[language],
        "baseline_sha256": _sha256(baseline),
        "refactored_sha256": _sha256(refactored),
        "contract_sha256": _sha256(json.dumps(
            baseline_surface, sort_keys=True, separators=(",", ":"))),
        "method_surface_sha256": _sha256("\n".join(baseline_api)),
        "baseline_deductive_proof": not bounded,
        "refactored_deductive_proof": not bounded,
        "contract_surface_preserved": True, "behavior_equivalence_proved": False,
        "refactor_verified": False,
        "baseline_verification": baseline_proof,
        "refactored_verification": refactored_proof,
        "semantic_surface": baseline_surface,
        "proof_trust": baseline_surface.get("proof_trust", {}),
    }


def verify_contract_preserving_refactor(baseline_path: str | Path,
                                        refactored_path: str | Path, *,
                                        runner: RefactorVerificationRunner | None = None) -> dict:
    """Verify both revisions and bind an unchanged public contract/API surface to their hashes.

    Loop invariants and decreases clauses are implementation proof hints and may change with
    control flow. This deliberately does not claim relational behavior equivalence; it establishes
    only that both revisions discharge the same public JML contract over the same method surface.
    """
    baseline_file, refactored_file = Path(baseline_path), Path(refactored_path)
    try:
        baseline = _read_text_exact(baseline_file)
        refactored = _read_text_exact(refactored_file)
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    from .polyglot_surface import language_for
    baseline_language = language_for(baseline_file.suffix.lower())
    refactored_language = language_for(refactored_file.suffix.lower())
    if baseline_language != refactored_language:
        return _fail("unsupported_language", "Baseline and refactored languages must match")
    if baseline_language in {"rust", "c", "cpp"}:
        return _verify_polyglot_refactor(
            baseline_file, refactored_file, baseline_language, runner=runner)
    if baseline_file.suffix.lower() not in {".java", ".jml"} or \
            refactored_file.suffix.lower() not in {".java", ".jml"}:
        return _fail("unsupported_language", "This profile supports Java/JML only")
    baseline_class, refactored_class = class_name(baseline), class_name(refactored)
    if not baseline_class or baseline_class != refactored_class:
        return _fail("class_identity_changed", "Public class identity must be preserved")
    if baseline_file.stem != baseline_class or refactored_file.stem != refactored_class:
        return _fail("source_layout_invalid",
                     "Each public Java class must use its matching source filename")
    # Private extracted helpers and their copied obligations are permitted, but
    # public contracts remain bound to the declarations they govern.
    baseline_surface = contract_surface(baseline, public_only=True)
    refactored_surface = contract_surface(refactored, public_only=True)
    surface_failure = _surface_failure(baseline_surface, refactored_surface)
    if surface_failure is not None:
        # Preserve the established API-specific failure code for callers.
        if surface_failure["code"] == "method_surface_changed":
            return surface_failure
        return surface_failure
    baseline_api = public_method_surface(baseline)
    refactored_api = public_method_surface(refactored)
    if not baseline_api or baseline_api != refactored_api:
        return _fail("method_surface_changed", "Public/protected method declarations differ")
    if baseline == refactored:
        return _fail("source_unchanged", "No refactoring change was detected")
    baseline_proof = _verification(
        baseline_file, runner=runner, stage="baseline")
    if baseline_proof["status"] != "VERIFIED":
        return _fail("baseline_not_verified", "Baseline failed OpenJML", baseline_proof)
    refactored_proof = _verification(
        refactored_file, runner=runner, stage="refactored")
    if refactored_proof["status"] != "VERIFIED":
        return _fail("refactored_not_verified", "Refactored source failed OpenJML",
                     refactored_proof)
    return {
        "status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED",
        "scope": "same_normalized_jml_and_public_method_surface_with_independent_esc",
        "baseline_sha256": _sha256(baseline),
        "refactored_sha256": _sha256(refactored),
        "contract_sha256": _sha256(json.dumps(
            baseline_surface, sort_keys=True, separators=(",", ":"))),
        "method_surface_sha256": _sha256("\n".join(baseline_api)),
        "baseline_deductive_proof": True, "refactored_deductive_proof": True,
        "contract_surface_preserved": True, "behavior_equivalence_proved": False,
        "refactor_verified": False,
        "baseline_verification": baseline_proof,
        "refactored_verification": refactored_proof,
        "semantic_surface": baseline_surface,
        "proof_trust": baseline_surface.get("proof_trust", {}),
    }


def verify_multifile_contract_refactor(baseline_path: str | Path,
                                       refactored_directory: str | Path, *,
                                       runner: RefactorVerificationRunner | None = None) -> dict:
    """Prove a preserved primary contract with all extracted collaborators in one ESC run."""
    baseline_file, directory = Path(baseline_path), Path(refactored_directory)
    try:
        baseline = _read_text_exact(baseline_file)
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    if baseline_file.suffix.lower() not in {".java", ".jml"}:
        return _fail("unsupported_language", "The baseline must be Java/JML")
    if not directory.is_dir():
        return _fail("refactored_directory_unavailable", "Refactored path must be a directory")
    primary = directory / baseline_file.name
    try:
        refactored_primary = _read_text_exact(primary)
    except OSError as exc:
        return _fail("primary_source_missing", str(exc))
    files = sorted(path for path in directory.iterdir()
                   if path.is_file() and path.suffix.lower() in {".java", ".jml"})
    if not files or any(path.is_symlink() for path in files):
        return _fail("unsafe_refactored_file_set", "A nonempty, non-symlink Java file set is required")
    if baseline_file.stem != class_name(baseline) or class_name(refactored_primary) != class_name(baseline):
        return _fail("primary_class_identity_changed", "Primary public class identity must be preserved")
    baseline_surface = contract_surface(baseline, public_only=True)
    primary_surface = contract_surface(refactored_primary, public_only=True)
    surface_failure = _surface_failure(baseline_surface, primary_surface, prefix="primary_")
    if surface_failure is not None:
        # Historical multifile callers use primary_contract_surface_changed for
        # both a missing baseline contract and an altered contract.
        if surface_failure["code"] == "primary_missing_trusted_contract":
            surface_failure["code"] = "primary_contract_surface_changed"
        return surface_failure
    baseline_api, primary_api = public_method_surface(baseline), public_method_surface(refactored_primary)
    if not baseline_api or baseline_api != primary_api:
        return _fail("primary_method_surface_changed", "Primary public/protected declarations differ")
    baseline_dependencies = [candidate for candidate in baseline_file.parent.glob("*.java")
                              if candidate != baseline_file]
    baseline_errors, baseline_trust = _java_fileset_trust_manifest(
        [baseline_file, *baseline_dependencies])
    refactored_errors, refactored_trust = _java_fileset_trust_manifest(files)
    if baseline_errors or refactored_errors:
        return _fail(
            "fileset_contract_syntax_unsupported",
            "Every Java source in the proof file set must satisfy the contract boundary",
            {"baseline": baseline_errors, "refactored": refactored_errors},
        )
    if baseline_trust != refactored_trust:
        return _fail(
            "proof_trust_changed",
            "Refactoring changed assumptions or verification controls in the proof file set",
            {"baseline": baseline_trust, "refactored": refactored_trust},
        )
    baseline_proof = _verification(
        baseline_file, baseline_dependencies, runner=runner, stage="baseline")
    if baseline_proof["status"] != "VERIFIED":
        return _fail("baseline_not_verified", "Baseline failed OpenJML", baseline_proof)
    refactored_proof = _verify_file_set(
        files, runner=runner, stage="refactored")
    if refactored_proof["status"] != "VERIFIED":
        return _fail("refactored_system_not_verified",
                     "Refactored file set failed OpenJML", refactored_proof)
    manifest = [{"path": path.name, "sha256": _sha256(_read_text_exact(path))}
                for path in files]
    return {"status": "VERIFIED", "claim": "MULTIFILE_REFACTOR_CONTRACT_PRESERVED",
            "scope": "primary_jml_api_preservation_plus_joint_refactored_fileset_esc",
            "baseline_sha256": _sha256(baseline), "primary_sha256": _sha256(refactored_primary),
            "contract_sha256": _sha256(json.dumps(
                baseline_surface, sort_keys=True, separators=(",", ":"))),
            "method_surface_sha256": _sha256("\n".join(baseline_api)),
            "refactored_manifest": manifest,
            "refactored_manifest_sha256": _sha256(json.dumps(manifest, sort_keys=True)),
            "baseline_deductive_proof": True, "refactored_fileset_deductive_proof": True,
            "contract_surface_preserved": True, "behavior_equivalence_proved": False,
            "heap_topology_equivalence_proved": False, "refactor_verified": False,
            "baseline_verification": baseline_proof,
            "refactored_verification": refactored_proof,
            "semantic_surface": baseline_surface,
            "proof_trust": {"baseline": baseline_trust,
                            "refactored": refactored_trust}}


def _verify_file_set(
        files: list[Path], *, runner: RefactorVerificationRunner | None = None,
        stage: str = "verification") -> dict:
    if runner is not None:
        return runner(stage, tuple(files), "java")
    check_exit, check_output = verify_files(files, mode="check")
    if check_exit != 0:
        return {"status": "FAIL", "gate": "check", "tool_status": classify(check_exit),
                "output": check_output}
    esc_exit, esc_output = verify_files(files, mode="esc")
    if esc_exit != 0:
        return {"status": "FAIL", "gate": "esc", "tool_status": classify(esc_exit),
                "output": esc_output}
    if has_dropped_vc(esc_output):
        return {"status": "FAIL", "gate": "esc", "tool_status": "VACUOUS_VERIFIED",
                "output": esc_output}
    return {"status": "VERIFIED", "gate": "esc", "tool_status": "VERIFIED"}


def _fail(code: str, message: str, evidence: dict | None = None) -> dict:
    result = {"status": "FAIL", "claim": "NO_PROOF", "code": code,
              "message": message, "contract_surface_preserved": False,
              "behavior_equivalence_proved": False, "refactor_verified": False}
    if evidence is not None:
        result["verification"] = evidence
    return result
