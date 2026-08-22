# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Non-evidentiary source screening for the qualified RefinedRust fragment."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import config


_RULES = (
    ("named_const_array_len", "KNOWN_BLOCKED", re.compile(r"\[[^;\]\n]+;\s*[A-Z][A-Z0-9_]*\s*\]")),
    ("iterator_enumerate", "KNOWN_BLOCKED", re.compile(r"\.iter(?:_mut)?\(\)\.enumerate\(\)")),
    ("slice_get_or_get_mut", "KNOWN_BLOCKED", re.compile(r"\.get(?:_mut)?\(")),
    ("slice_type", "UNKNOWN", re.compile(r"&(?:mut\s+)?\[[^;\]]+\]")),
    ("closure", "UNKNOWN", re.compile(r"\|[^|\n]*\|")),
    ("async", "UNKNOWN", re.compile(r"\basync\b|\.await\b")),
    ("atomic", "UNKNOWN", re.compile(r"\bAtomic(?:Bool|Usize|U8|U16|U32|U64|Ptr)\b")),
    ("allocation", "UNKNOWN", re.compile(r"\b(?:Box|Vec|String)::|\b(?:alloc|dealloc)\s*\(")),
    ("trait_or_generic", "LIKELY_SUPPORTED", re.compile(r"\btrait\b|impl\s*<|\bimpl\s+\w+\s+for\b")),
    ("result_try_branch", "KNOWN_BLOCKED", re.compile(r"\?")),
    ("result_or_option", "LIKELY_SUPPORTED", re.compile(r"\b(?:Result|Option)<")),
    ("enum_match", "LIKELY_SUPPORTED", re.compile(r"\bmatch\b")),
    ("direct_scalar_field_mutation", "SUPPORTED", re.compile(r"self\.\w+\s*(?:=|\+=|-=)")),
    ("scalar_field", "SUPPORTED", re.compile(r"^\s*(?:pub\s+)?\w+\s*:\s*(?:bool|u8|u16|u32|u64|usize|i8|i16|i32|i64|isize),", re.MULTILINE)),
)

_SEVERITY = {"SUPPORTED": 0, "LIKELY_SUPPORTED": 1, "UNKNOWN": 2, "KNOWN_BLOCKED": 3}

_BOUNDARY_IDS = {
    "named_const_array_len": "named_const_array_len",
    "iterator_enumerate": "iterator_enumerate_lowering",
    "slice_get_or_get_mut": "slice_get_mut_trait_semantics",
    "trait_or_generic": "generic_local_trait_impl_registration",
    "result_try_branch": "result_try_branch",
}


def _boundary_statuses() -> dict[str, str]:
    try:
        ledger = json.loads(Path(config.REFINEDRUST_BOUNDARY_LEDGER).read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {item["id"]: item["status"] for item in ledger.get("boundaries", [])}


def _effective_classification(name: str, fallback: str, statuses: dict[str, str]) -> str:
    status = statuses.get(_BOUNDARY_IDS.get(name, ""))
    if status in {"OPEN", "OPEN_ICE"}:
        return "KNOWN_BLOCKED"
    if status in {"CLOSED_LOCALLY", "QUALIFIED_SUPPORTED"}:
        return "LIKELY_SUPPORTED"
    return fallback


def scan_refinedrust_feasibility(path: Path) -> dict:
    """Classify syntax only; never infer verification or correctness."""
    source = path.read_text()
    statuses = _boundary_statuses()
    findings = [
        {"construct": name,
         "classification": _effective_classification(name, classification, statuses),
         "boundary_status": statuses.get(_BOUNDARY_IDS.get(name, ""), "UNTRACKED")}
        for name, classification, pattern in _RULES
        if pattern.search(source)
    ]
    overall = max(
        (item["classification"] for item in findings),
        key=_SEVERITY.__getitem__,
        default="UNKNOWN",
    )
    return {
        "source": path.as_posix(),
        "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "classification": overall,
        "findings": findings,
        "claim": "NO_PROOF",
    }


def rank_refinedrust_candidates(paths: list[Path]) -> list[dict]:
    """Rank syntax candidates without promoting likely support to evidence."""
    reports = [scan_refinedrust_feasibility(path) for path in paths]
    return sorted(
        reports,
        key=lambda report: (
            _SEVERITY[report["classification"]],
            sum(item["classification"] == "KNOWN_BLOCKED" for item in report["findings"]),
            report["source"],
        ),
    )
