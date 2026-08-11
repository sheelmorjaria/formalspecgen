# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Dataclasses for run artifacts.

VC / Attempt are ported from formalspecDD; SpecDraft / SpecResult are the NL->JML
additions for this project.
"""
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class VC:
    """One validation failure parsed from OpenJML output.

    Works for both the `-esc` `verify:` format (parse_vcs.py) and the `-check`/`-parse`
    `error:`/`warning:` format (parse_check.py).
    """
    file: str
    line: int
    category: str          # Postcondition | error | warning | ArithmeticOperationRange | ...
    method: Optional[str] = None
    decl: Optional[str] = None      # ESC spec-clause failures: declfile:declline:
    detail: Optional[str] = None    # -check message, or ESC range-check detail
    raw: str = ""


@dataclass
class Attempt:
    n: int
    exit_code: int
    status: str            # VERIFIED | COMPILE_FAILED | VERIFY_FAILED | TIMEOUT | API_ERROR | UNKNOWN
    vcs: List[VC] = field(default_factory=list)
    note: str = ""
    tokens: dict = field(default_factory=dict)   # {input, output, total}
    backend: str = "openjml"
    candidate_hash: str = ""
    failure_fingerprints: List[str] = field(default_factory=list)
    gates: List[dict] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


# ---- NL -> JML additions ----

@dataclass
class SpecDraft:
    """One LLM generation: a JML-annotated Java stub + analyst metadata."""
    stub: str                                   # full .java source (skeleton + //@ annotations)
    assumptions: List[str] = field(default_factory=list)
    missing_info: List[str] = field(default_factory=list)


@dataclass
class SpecResult:
    nl: str
    final_status: str
    attempts: List[Attempt] = field(default_factory=list)
    model: str = ""
    provider: str = ""
    duration_s: float = 0.0
    stub_path: str = ""
    assumptions: List[str] = field(default_factory=list)
    missing_info: List[str] = field(default_factory=list)
    tokens: dict = field(default_factory=dict)
    stop_reason: str = ""
    pipeline_state: str = "REQUIREMENTS"
    transitions: List[dict] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    claim: str = "STATIC_CHECK"


@dataclass
class RefineResult:
    """Outcome of a no-clobber refinement (pipeline/refine.py). Non-destructive: the caller
    decides whether to apply new_stub after reviewing diff + conflicts."""
    instruction: str
    new_stub: str
    check_ok: bool
    check_errors: List[str] = field(default_factory=list)
    diff: dict = field(default_factory=dict)          # {added, removed, common} clause sets
    conflicts: List[str] = field(default_factory=list)  # locked clauses the model altered
    assumptions: List[str] = field(default_factory=list)
    missing_info: List[str] = field(default_factory=list)
    model: str = ""
    error: str = ""
    duration_s: float = 0.0
    status: str = "CANDIDATE"
    terminal: bool = False
    candidate_stub: str = ""
