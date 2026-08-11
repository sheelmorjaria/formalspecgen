# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Typed assurance profiles and fail-closed evidence-to-claim policy."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class AssuranceLevel(str, Enum):
    CRITICAL = "critical"
    STANDARD = "standard"
    LIGHTWEIGHT = "lightweight"


class GatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    required: bool
    skip_reason: str = ""


_ORDER = ("javac", "spec_lint", "openjml_check", "tla", "openjml_esc",
          "boundary_fallback", "rac_junit")


def parse_assurance_level(value: str | AssuranceLevel | None) -> AssuranceLevel:
    if isinstance(value, AssuranceLevel):
        return value
    normalized = str(value or AssuranceLevel.CRITICAL.value).strip().lower()
    try:
        return AssuranceLevel(normalized)
    except ValueError as exc:
        raise ValueError(
            f"unknown assurance level {value!r}; expected critical, standard, or lightweight") from exc


def gate_plan(value: str | AssuranceLevel | None) -> list[GatePolicy]:
    level = parse_assurance_level(value)
    required = {
        AssuranceLevel.CRITICAL: set(_ORDER[:-1]),
        AssuranceLevel.STANDARD: {"javac", "spec_lint", "openjml_check", "rac_junit"},
        AssuranceLevel.LIGHTWEIGHT: {"javac", "spec_lint", "rac_junit"},
    }[level]
    return [GatePolicy(
        name=name, required=name in required,
        skip_reason="" if name in required else f"Assurance level is {level.value}")
        for name in _ORDER]


def assurance_verdict(value: str | AssuranceLevel | None,
                      gate_statuses: dict[str, str]) -> dict:
    """Classify completed evidence without promoting samples into proof claims."""
    level = parse_assurance_level(value)
    plan = gate_plan(level)
    records = []
    failed = []
    for gate in plan:
        status = gate_statuses.get(gate.name, "NOT_RUN") if gate.required else "SKIPPED"
        reason = gate.skip_reason if not gate.required else ""
        records.append({"gate": gate.name, "required": gate.required,
                        "status": status, "reason": reason})
        accepted = {"PASS", "VERIFIED", "TESTS_PASSED"}
        if gate.name == "boundary_fallback":
            accepted.add("NOT_APPLICABLE")
        if gate.required and status not in accepted:
            failed.append(gate.name)

    if failed:
        status, claim = "ASSURANCE_INCOMPLETE", "NO_PROOF"
    elif level is AssuranceLevel.CRITICAL:
        status, claim = "VERIFIED", "DEDUCTIVE_PROOF"
    elif level is AssuranceLevel.STANDARD:
        status, claim = "STATIC_CHECKED_RUNTIME_TESTED", "RUNTIME_SAMPLE"
    else:
        status, claim = "COMPILED_LINTED", "RUNTIME_SAMPLE"
    return {
        "final_status": status,
        "assurance_level": level.value,
        "gates": records,
        "failed_required_gates": failed,
        "final_claim_type": claim,
        "source_refinement_proved": level is AssuranceLevel.CRITICAL and not failed,
        "deductive_proof_provided": level is AssuranceLevel.CRITICAL and not failed,
    }
