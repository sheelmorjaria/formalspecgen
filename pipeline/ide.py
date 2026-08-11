# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Client-facing deterministic transforms and backend recommendations.

Postprocessor passes are statically imported from the bundled ``formalspec_core`` package.
"""
import difflib
import re

from . import postprocess as local_postprocess
from .jml_to_dafny import translate_jml_to_dafny, UnsupportedBoundary

PASS_NAMES = (
    "strip_exit_invariants",
    "strip_result_from_invariants",
    "fix_inner_loop_spec_placement",
    "inject_overflow_bounds",
    "inject_bitshift_bounds",
    "inject_sum_invariant",
    "inject_sum_helper",
    "inject_bidirectional_old",
    "guard_array_access",
    "strengthen_sorted",
    "inject_pure",
    "inject_nonlinear_index_assume",
    "guard_exclusion_invariants",
)


def apply_passes(code: str, selected=None) -> dict:
    """Apply selected passes in canonical order and report every material change."""
    requested = set(selected or PASS_NAMES)
    unknown = sorted(requested.difference(PASS_NAMES))
    if unknown:
        raise ValueError("unknown postprocessor passes: " + ", ".join(unknown))
    original = current = code
    reports = []
    for name in PASS_NAMES:
        if name not in requested:
            continue
        before = current
        current = getattr(local_postprocess, name)(current)
        changed = current != before
        report = {"name": name, "changed": changed}
        if changed:
            report["diff"] = "\n".join(difflib.unified_diff(
                before.splitlines(), current.splitlines(),
                fromfile=f"before/{name}", tofile=f"after/{name}", lineterm=""))
        reports.append(report)
    return {
        "original_code": original,
        "code": current,
        "changed": current != original,
        "passes": reports,
        "proof_relevant_change": current != original,
        "requires_human_acceptance": current != original,
        "accepted": False,
        "claim": "TRANSFORMATION",
    }


def route_backend(code: str) -> dict:
    """Recommend a proven backend without claiming unavailable translation support."""
    suggestions = discover_passes(code)
    if re.search(r"\b(synchronized|Thread|Runnable|Lock|mutex|semaphore|atomic|deadlock)\b", code, re.I):
        return {"backend": "tla", "executable": True,
                "reasons": ["thread/lock behavior requires explicit interleaving exploration"],
                "suggested_passes": suggestions,
                "message": "TLA+/TLC is available for a bounded design-level concurrency model."}
    reasons = []
    if re.search(r"\\old\s*\(\s*\w+\s*\)\s*\[", code):
        reasons.append("old array heap snapshots are better encoded as Dafny sequences")
    if "\\num_of" in code or "permutation" in code.lower():
        reasons.append("permutation properties map to Dafny's native multiset")
    if re.search(r"\b(recursive|gcd)\b", code, re.IGNORECASE):
        reasons.append("recursive induction is better supported by Dafny functions")
    if reasons:
        try:
            translation = translate_jml_to_dafny(code)
            return {"backend": "dafny", "executable": True, "reasons": reasons,
                    "boundary": translation.boundary,
                    "suggested_passes": suggestions,
                    "message": "This shape is supported by the targeted Dafny boundary translator."}
        except UnsupportedBoundary as exc:
            return {"backend": "dafny", "executable": False,
                    "reasons": reasons + [str(exc)],
                    "suggested_passes": suggestions,
                    "message": "Dafny is recommended, but this exact shape is not safely translatable."}
    return {"backend": "jml", "executable": True,
            "reasons": ["the specification fits the automated OpenJML/Z3 path"],
            "suggested_passes": suggestions,
            "message": "OpenJML/Z3 is available for this specification."}


def discover_passes(code: str) -> list[dict]:
    """Suggest deterministic passes from source features without mutating code."""
    rules = [
        ("inject_bitshift_bounds", r"(?:<<|>>)", "bit shifts need a bounded shift count"),
        ("inject_overflow_bounds", r"\b\w+\s*\*\s*\w+\b", "non-linear int arithmetic may overflow"),
        ("inject_sum_helper", r"\\sum\b", "OpenJML may drop aggregate sum obligations"),
        ("inject_sum_invariant", r"\\sum\b[\s\S]*\b(?:while|for)\s*\(", "a partial-sum loop invariant may be required"),
        ("inject_bidirectional_old", r"\\old\s*\(\s*\w+\s*\)\s*\[", "old-array heap reasoning needs a stronger encoding"),
        ("guard_array_access", r"\[[^]]+\]\s*(?:=|;)", "array accesses require explicit index guards"),
        ("strengthen_sorted", r"(?:sorted|\\forall[^;]*(?:<=|<)[^;]*\[)", "sortedness proofs often need pairwise strengthening"),
        ("inject_nonlinear_index_assume", r"\[[^]]*[*/%][^]]*\]", "non-linear array indices need an explicit range fact"),
        ("fix_inner_loop_spec_placement", r"(?:while|for)\s*\([^)]*\)\s*\{\s*//@\s*(?:loop_invariant|decreases)", "JML loop specifications must precede the loop"),
        ("guard_exclusion_invariants", r"public\s+invariant\s+!\(\s*\w+\s*==\s*-?\d+\s*&&\s*\w+\s*==\s*-?\d+\s*\)",
         "assignments must preserve the reviewed two-field exclusion invariant"),
    ]
    return [{"name": name, "reason": reason} for name, pattern, reason in rules
            if re.search(pattern, code, re.I)]
