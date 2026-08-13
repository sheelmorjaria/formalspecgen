# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed evidence for a narrow Java/JML contract-preserving refactor."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .jml_io import class_name, extract_clauses
from .verify import classify, has_dropped_vc, verify


_METHOD = re.compile(
    r"(?m)^\s*((?:public|protected)\s+(?:(?:static|final|synchronized|abstract)\s+)*"
    r"(?:<[^{;()]+>\s+)?(?:[\w.$<>\[\],?]+\s+)?[A-Za-z_$][\w$]*\s*"
    r"\([^)]*\)(?:\s+throws\s+[^{;]+)?)(?=\s*[;{])")


def _sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def public_method_surface(source: str) -> list[str]:
    """Extract a formatting-insensitive public/protected declaration surface."""
    return sorted(re.sub(r"\s+", " ", match.group(1)).strip()
                  for match in _METHOD.finditer(source))


def _verification(path: Path) -> dict:
    check_exit, check_output = verify(path, mode="check")
    if check_exit != 0:
        return {"status": "FAIL", "gate": "check", "tool_status": classify(check_exit),
                "output": check_output}
    esc_exit, esc_output = verify(path, mode="esc")
    if esc_exit != 0:
        return {"status": "FAIL", "gate": "esc", "tool_status": classify(esc_exit),
                "output": esc_output}
    if has_dropped_vc(esc_output):
        return {"status": "FAIL", "gate": "esc", "tool_status": "VACUOUS_VERIFIED",
                "output": esc_output}
    return {"status": "VERIFIED", "gate": "esc", "tool_status": "VERIFIED"}


def verify_contract_preserving_refactor(baseline_path: str | Path,
                                        refactored_path: str | Path) -> dict:
    """Verify both revisions and bind an unchanged contract/API surface to their hashes.

    This deliberately does not claim relational behavior equivalence. It establishes only that
    both revisions discharge the same syntactic JML contract over the same visible method surface.
    """
    baseline_file, refactored_file = Path(baseline_path), Path(refactored_path)
    try:
        baseline = baseline_file.read_text(encoding="utf-8")
        refactored = refactored_file.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    if baseline_file.suffix.lower() not in {".java", ".jml"} or \
            refactored_file.suffix.lower() not in {".java", ".jml"}:
        return _fail("unsupported_language", "This profile supports Java/JML only")
    baseline_class, refactored_class = class_name(baseline), class_name(refactored)
    if not baseline_class or baseline_class != refactored_class:
        return _fail("class_identity_changed", "Public class identity must be preserved")
    if baseline_file.stem != baseline_class or refactored_file.stem != refactored_class:
        return _fail("source_layout_invalid",
                     "Each public Java class must use its matching source filename")
    baseline_contract = sorted(extract_clauses(baseline))
    refactored_contract = sorted(extract_clauses(refactored))
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


def _fail(code: str, message: str, evidence: dict | None = None) -> dict:
    result = {"status": "FAIL", "claim": "NO_PROOF", "code": code,
              "message": message, "contract_surface_preserved": False,
              "behavior_equivalence_proved": False, "refactor_verified": False}
    if evidence is not None:
        result["verification"] = evidence
    return result
