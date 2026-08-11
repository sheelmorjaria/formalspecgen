# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Evidence-backed assurance-profile routing for implementation synthesis."""
from __future__ import annotations

import json
from pathlib import Path

from .assurance import (
    AssuranceLevel, assurance_verdict, parse_assurance_level, refinement_gate,
)
from .implementation import synthesize_implementation
from .rac import collect_rac_evidence
from .spec_lint import blocking_findings, lint_spec
from .tla_backend import generate_and_check
from .validate import check_stub


def run_assured_implementation(stub: str, assurance_level: str = "critical", *,
                               provider: str = "glm", model: str | None = None,
                               out_dir: str | Path | None = None, max_attempts: int = 5,
                               resample_budget: int = 1, feedback_budget: int = 4,
                               accepted_passes: list[str] | None = None,
                               clarifications: str = "", abstraction: str = "atomic_operations",
                               candidate: str | None = None, on_event=None) -> dict:
    """Run only the gates required by a profile and derive the claim from their evidence."""
    level = parse_assurance_level(assurance_level)
    statuses: dict[str, str] = {}
    evidence: dict[str, object] = {}

    lint = lint_spec(stub)
    blockers = blocking_findings(lint)
    statuses["spec_lint"] = "PASS" if not blockers else "FAIL"
    evidence["spec_lint"] = {"findings": lint, "blocking": blockers}
    if blockers:
        verdict = assurance_verdict(level, statuses)
        return {**verdict, "implementation": None, "evidence": evidence}

    if level is not AssuranceLevel.LIGHTWEIGHT:
        checked, errors = check_stub(stub)
        statuses["openjml_check"] = "PASS" if checked else "FAIL"
        evidence["openjml_check"] = {"errors": errors}
        if not checked:
            verdict = assurance_verdict(level, statuses)
            return {**verdict, "implementation": None, "evidence": evidence}

    if level is AssuranceLevel.CRITICAL:
        architecture = generate_and_check(stub, clarifications=clarifications,
                                          abstraction=abstraction)
        statuses["tla"] = "VERIFIED" if architecture.get("status") == "VERIFIED" else "FAIL"
        evidence["tla"] = architecture
        if statuses["tla"] != "VERIFIED":
            verdict = assurance_verdict(level, statuses)
            return {**verdict, "implementation": None, "evidence": evidence}

    mode = {AssuranceLevel.CRITICAL: "esc", AssuranceLevel.STANDARD: "check",
            AssuranceLevel.LIGHTWEIGHT: "compile"}[level]
    implementation = synthesize_implementation(
        stub, provider=provider, model=model, out_dir=out_dir, max_attempts=max_attempts,
        resample_budget=resample_budget, feedback_budget=feedback_budget,
        accepted_passes=accepted_passes, candidate=candidate, on_event=on_event,
        verification_mode=mode)
    evidence["implementation"] = implementation
    final = implementation.get("final_status")
    statuses["javac"] = "PASS" if final not in {
        "COMPILE_FAILED", "INVALID_STUB", "API_ERROR", "TRUST_BOUNDARY_VIOLATION", "NO_ATTEMPT"} else "FAIL"

    if level is AssuranceLevel.CRITICAL:
        statuses["openjml_esc"] = "VERIFIED" if final == "VERIFIED" else "FAIL"
        statuses["boundary_fallback"] = "NOT_APPLICABLE"
        refinement = refinement_gate(
            stub, implementation.get("implementation_code", ""), architecture,
            esc_verified=statuses["openjml_esc"] == "VERIFIED")
        evidence["refinement"] = refinement
        statuses["refinement"] = refinement["status"]
    elif level is AssuranceLevel.STANDARD:
        statuses["openjml_check"] = "PASS" if final == "STATIC_CHECKED" else "FAIL"
        if final == "STATIC_CHECKED" and implementation.get("implementation_code"):
            runtime = collect_rac_evidence(implementation["implementation_code"], provider=provider)
            evidence["rac_junit"] = runtime
            statuses["rac_junit"] = ("TESTS_PASSED" if
                runtime.get("status") == "NO_RUNTIME_FAILURE_FOUND" and runtime.get("passed", 0) > 0
                else "FAIL")

    verdict = assurance_verdict(level, statuses)
    result = {**verdict, "implementation": implementation, "evidence": evidence}
    if out_dir:
        root = Path(out_dir)
        root.mkdir(parents=True, exist_ok=True)
        (root / "assurance-verdict.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
