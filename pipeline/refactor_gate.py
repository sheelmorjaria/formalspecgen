# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed evidence for a narrow Java/JML contract-preserving refactor."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .jml_io import class_name, extract_clauses
from .verify import classify, has_dropped_vc, verify, verify_files


_METHOD = re.compile(
    r"(?m)^\s*((?:public|protected)\s+(?:(?:static|final|synchronized|abstract)\s+)*"
    r"(?:<[^{;()]+>\s+)?(?:[\w.$<>\[\],?]+\s+)?[A-Za-z_$][\w$]*\s*"
    r"\([^)]*\)(?:\s+throws\s+[^{;]+)?)(?=\s*[;{])")


def _public_contract_clauses(source: str) -> list[str]:
    """Return observable JML clauses, excluding implementation proof hints.

    Loop/object-safety invariants and termination measures describe a particular
    implementation's proof shape. A refactor may strengthen them, so they are not
    treated as changed public API clauses.
    """
    return sorted({clause for clause in extract_clauses(source)
                   if not clause.startswith(("loop_invariant", "invariant", "private invariant", "public invariant", "decreases", "assume"))})


def _sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def public_method_surface(source: str) -> list[str]:
    """Extract a formatting-insensitive public/protected declaration surface."""
    return sorted(re.sub(r"\s+", " ", match.group(1)).strip()
                  for match in _METHOD.finditer(source))


def _verification(path: Path, extra_files: list[Path] | None = None) -> dict:
    sources = [path, *(extra_files or [])]
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


def _polyglot_verification(source_file: Path, language: str) -> dict:
    """Re-verify one non-Java revision with its native prover (esc equivalent)."""
    code = source_file.read_text(encoding="utf-8")
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
                              language: str) -> dict:
    """Contract-preserving gate for rust (Prusti), c (Frama-C), and cpp (ESBMC)."""
    from .polyglot_surface import contract_clauses, public_api_surface

    baseline = baseline_file.read_text(encoding="utf-8")
    refactored = refactored_file.read_text(encoding="utf-8")
    baseline_contract = contract_clauses(baseline, language)
    refactored_contract = contract_clauses(refactored, language)
    if not baseline_contract:
        return _fail("missing_trusted_contract",
                     f"Baseline contains no {language} contract clauses")
    # Subset, not equality: every baseline clause must survive verbatim, and
    # added clauses on new items (an extracted helper's copied contract, a
    # strategy trait's method declaration) are permitted — mirroring the
    # Java lane, where private helpers may repeat the public obligations,
    # and this gate's own API rule (baseline signatures must survive).
    if not baseline_contract <= refactored_contract:
        return _fail("contract_surface_changed",
                     "Every baseline contract clause must survive the refactor")
    baseline_api = public_api_surface(baseline, language)
    refactored_api = public_api_surface(refactored, language)
    if not baseline_api:
        return _fail("method_surface_changed", "Baseline exposes no public API surface")
    # An extracted helper may ADD a signature; contract preservation requires
    # every baseline signature to survive verbatim (subset, not equality).
    if not set(baseline_api) <= set(refactored_api):
        return _fail("method_surface_changed",
                     "Every baseline public signature must survive the refactor")
    if baseline == refactored:
        return _fail("source_unchanged", "No refactoring change was detected")
    baseline_proof = _polyglot_verification(baseline_file, language)
    if baseline_proof["status"] != "VERIFIED":
        return _fail("baseline_not_verified",
                     f"Baseline failed native {language} verification", baseline_proof)
    refactored_proof = _polyglot_verification(refactored_file, language)
    if refactored_proof["status"] != "VERIFIED":
        return _fail("refactored_not_verified",
                     f"Refactored source failed native {language} verification",
                     refactored_proof)
    bounded = language == "cpp"
    return {
        "status": "VERIFIED",
        "claim": "BOUNDED_REFACTOR_CONTRACT_PRESERVED" if bounded
                 else "REFACTOR_CONTRACT_PRESERVED",
        "scope": ("bounded_native_contract_check_same_api_surface" if bounded else
                  "same_normalized_native_contract_and_public_api_surface_with_independent_proofs"),
        "language": language, "verifier": {"rust": "prusti", "c": "frama-c-wp",
                                           "cpp": "esbmc"}[language],
        "baseline_sha256": _sha256(baseline),
        "refactored_sha256": _sha256(refactored),
        "contract_sha256": _sha256("\n".join(sorted(baseline_contract))),
        "method_surface_sha256": _sha256("\n".join(baseline_api)),
        "baseline_deductive_proof": not bounded,
        "refactored_deductive_proof": not bounded,
        "contract_surface_preserved": True, "behavior_equivalence_proved": False,
        "refactor_verified": False,
    }


def verify_contract_preserving_refactor(baseline_path: str | Path,
                                        refactored_path: str | Path) -> dict:
    """Verify both revisions and bind an unchanged public contract/API surface to their hashes.

    Loop invariants and decreases clauses are implementation proof hints and may change with
    control flow. This deliberately does not claim relational behavior equivalence; it establishes
    only that both revisions discharge the same public JML contract over the same method surface.
    """
    baseline_file, refactored_file = Path(baseline_path), Path(refactored_path)
    try:
        baseline = baseline_file.read_text(encoding="utf-8")
        refactored = refactored_file.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    from .polyglot_surface import language_for
    baseline_language = language_for(baseline_file.suffix.lower())
    refactored_language = language_for(refactored_file.suffix.lower())
    if baseline_language != refactored_language:
        return _fail("unsupported_language", "Baseline and refactored languages must match")
    if baseline_language in {"rust", "c", "cpp"}:
        return _verify_polyglot_refactor(baseline_file, refactored_file, baseline_language)
    if baseline_file.suffix.lower() not in {".java", ".jml"} or \
            refactored_file.suffix.lower() not in {".java", ".jml"}:
        return _fail("unsupported_language", "This profile supports Java/JML only")
    baseline_class, refactored_class = class_name(baseline), class_name(refactored)
    if not baseline_class or baseline_class != refactored_class:
        return _fail("class_identity_changed", "Public class identity must be preserved")
    if baseline_file.stem != baseline_class or refactored_file.stem != refactored_class:
        return _fail("source_layout_invalid",
                     "Each public Java class must use its matching source filename")
    # A private extracted helper may repeat the public method's obligations so ESC can
    # reason modularly. Repetition does not alter the normalized contract surface.
    baseline_contract = _public_contract_clauses(baseline)
    refactored_contract = _public_contract_clauses(refactored)
    if not baseline_contract:
        return _fail("missing_trusted_contract", "Baseline contains no JML contract clauses")
    if baseline_contract != refactored_contract:
        return _fail("contract_surface_changed", "Normalized JML clauses differ")
    baseline_api = public_method_surface(baseline)
    refactored_api = public_method_surface(refactored)
    if not baseline_api or baseline_api != refactored_api:
        return _fail("method_surface_changed", "Public/protected method declarations differ")
    if baseline == refactored:
        return _fail("source_unchanged", "No refactoring change was detected")
    baseline_proof = _verification(baseline_file)
    if baseline_proof["status"] != "VERIFIED":
        return _fail("baseline_not_verified", "Baseline failed OpenJML", baseline_proof)
    refactored_proof = _verification(refactored_file)
    if refactored_proof["status"] != "VERIFIED":
        return _fail("refactored_not_verified", "Refactored source failed OpenJML",
                     refactored_proof)
    return {
        "status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED",
        "scope": "same_normalized_jml_and_public_method_surface_with_independent_esc",
        "baseline_sha256": _sha256(baseline),
        "refactored_sha256": _sha256(refactored),
        "contract_sha256": _sha256("\n".join(baseline_contract)),
        "method_surface_sha256": _sha256("\n".join(baseline_api)),
        "baseline_deductive_proof": True, "refactored_deductive_proof": True,
        "contract_surface_preserved": True, "behavior_equivalence_proved": False,
        "refactor_verified": False,
    }


def verify_multifile_contract_refactor(baseline_path: str | Path,
                                       refactored_directory: str | Path) -> dict:
    """Prove a preserved primary contract with all extracted collaborators in one ESC run."""
    baseline_file, directory = Path(baseline_path), Path(refactored_directory)
    try:
        baseline = baseline_file.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    if baseline_file.suffix.lower() not in {".java", ".jml"}:
        return _fail("unsupported_language", "The baseline must be Java/JML")
    if not directory.is_dir():
        return _fail("refactored_directory_unavailable", "Refactored path must be a directory")
    primary = directory / baseline_file.name
    try:
        refactored_primary = primary.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("primary_source_missing", str(exc))
    files = sorted(path for path in directory.iterdir()
                   if path.is_file() and path.suffix.lower() in {".java", ".jml"})
    if not files or any(path.is_symlink() for path in files):
        return _fail("unsafe_refactored_file_set", "A nonempty, non-symlink Java file set is required")
    if baseline_file.stem != class_name(baseline) or class_name(refactored_primary) != class_name(baseline):
        return _fail("primary_class_identity_changed", "Primary public class identity must be preserved")
    baseline_contract = _public_contract_clauses(baseline)
    primary_contract = _public_contract_clauses(refactored_primary)
    if not baseline_contract or baseline_contract != primary_contract:
        return _fail("primary_contract_surface_changed", "Primary normalized JML clauses differ")
    baseline_api, primary_api = public_method_surface(baseline), public_method_surface(refactored_primary)
    if not baseline_api or baseline_api != primary_api:
        return _fail("primary_method_surface_changed", "Primary public/protected declarations differ")
    baseline_dependencies = [candidate for candidate in baseline_file.parent.glob("*.java")
                              if candidate != baseline_file]
    baseline_proof = _verification(baseline_file, baseline_dependencies)
    if baseline_proof["status"] != "VERIFIED":
        return _fail("baseline_not_verified", "Baseline failed OpenJML", baseline_proof)
    refactored_proof = _verify_file_set(files)
    if refactored_proof["status"] != "VERIFIED":
        return _fail("refactored_system_not_verified",
                     "Refactored file set failed OpenJML", refactored_proof)
    manifest = [{"path": path.name, "sha256": _sha256(path.read_text(encoding="utf-8"))}
                for path in files]
    return {"status": "VERIFIED", "claim": "MULTIFILE_REFACTOR_CONTRACT_PRESERVED",
            "scope": "primary_jml_api_preservation_plus_joint_refactored_fileset_esc",
            "baseline_sha256": _sha256(baseline), "primary_sha256": _sha256(refactored_primary),
            "contract_sha256": _sha256("\n".join(baseline_contract)),
            "method_surface_sha256": _sha256("\n".join(baseline_api)),
            "refactored_manifest": manifest,
            "refactored_manifest_sha256": _sha256(json.dumps(manifest, sort_keys=True)),
            "baseline_deductive_proof": True, "refactored_fileset_deductive_proof": True,
            "contract_surface_preserved": True, "behavior_equivalence_proved": False,
            "heap_topology_equivalence_proved": False, "refactor_verified": False}


def _verify_file_set(files: list[Path]) -> dict:
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
