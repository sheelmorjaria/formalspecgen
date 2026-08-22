# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Non-evidentiary production-source ranking for the pinned Verus fragment."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import config


_RULES = (
    ("iterator_traversal_semantics", "KNOWN_BLOCKED",
     re.compile(r"\.iter_mut\(\)\.enumerate\(\)")),
    ("get_mut_frame_semantics", "KNOWN_BLOCKED", re.compile(r"\.get_mut\(")),
    ("occupancy_count_correspondence", "KNOWN_BLOCKED",
     re.compile(r"\.iter\(\)\.filter\([^\n]+\)\.count\(\)")),
    ("iterator_adaptors", "UNKNOWN", re.compile(r"\.(?:flatten|any|map_err)\(")),
    ("slice_or_range", "UNKNOWN", re.compile(r"&(?:mut\s+)?\[[^;\]]+\]|\.get\(")),
    ("result_try", "UNKNOWN", re.compile(r"\?")),
    ("trait_or_generic", "UNKNOWN", re.compile(r"\btrait\b|impl\s*<")),
    ("atomics_or_concurrency", "REJECTED", re.compile(r"\bAtomic\w+|\bunsafe\b")),
    ("dynamic_allocation", "REJECTED", re.compile(r"\b(?:Box|Vec|String)::|\b(?:alloc|dealloc)\s*\(")),
    ("direct_scalar_mutation", "SUPPORTED", re.compile(r"self\.\w+\s*(?:=|\+=|-=)")),
    ("bounded_array", "SUPPORTED", re.compile(r"\[[^;\]\n]+;\s*[A-Z][A-Z0-9_]*\s*\]")),
    ("enum_or_match", "LIKELY_SUPPORTED", re.compile(r"\benum\b|\bmatch\b")),
)

_SEVERITY = {"SUPPORTED": 0, "LIKELY_SUPPORTED": 1, "UNKNOWN": 2,
             "KNOWN_BLOCKED": 3, "REJECTED": 4}
_NON_PRODUCTION_PARTS = {"refinement", "refinedrust_smoke", "verus_allocator", "verus_smoke"}


def _bridge_statuses() -> dict[str, str]:
    try:
        ledger = json.loads(Path(config.VERUS_BOUNDARY_LEDGER).read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {item["id"]: item["status"] for item in ledger.get("bridges", [])}


def scan_verus_feasibility(path: Path, *, semantic_usefulness: int = 0,
                           abstract_model: str | None = None) -> dict:
    """Classify source syntax and usefulness without making a proof claim."""
    source = path.read_text()
    bridge_statuses = _bridge_statuses()
    findings = []
    for construct, fallback, pattern in _RULES:
        if not pattern.search(source):
            continue
        status = bridge_statuses.get(construct, "UNTRACKED")
        classification = "KNOWN_BLOCKED" if status == "NO_PROOF" else fallback
        findings.append({"construct": construct, "classification": classification,
                         "boundary_status": status})
    overall = max((item["classification"] for item in findings),
                  key=_SEVERITY.__getitem__, default="UNKNOWN")
    blocked = sum(item["classification"] == "KNOWN_BLOCKED" for item in findings)
    unknown = sum(item["classification"] == "UNKNOWN" for item in findings)
    rejected = sum(item["classification"] == "REJECTED" for item in findings)
    mutation_points = len(re.findall(r"(?:return\s+Err|\+=|-=|=\s*(?:true|false|Some|None))", source))
    score = semantic_usefulness + min(mutation_points, 10) * 3 - blocked * 30 - unknown * 8 - rejected * 100
    return {
        "source": path.as_posix(),
        "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "classification": overall,
        "score": score,
        "semantic_usefulness": semantic_usefulness,
        "mutation_points": mutation_points,
        "abstract_model": abstract_model,
        "safe_rust": not any(item["construct"] == "atomics_or_concurrency" for item in findings),
        "findings": findings,
        "claim": "NO_PROOF",
    }


def rank_verus_candidates(candidates: list[tuple[Path, int, str | None]]) -> list[dict]:
    """Rank exact production modules; scores guide probing but never mint evidence."""
    reports = [scan_verus_feasibility(path, semantic_usefulness=usefulness,
                                      abstract_model=model)
               for path, usefulness, model in candidates]
    return sorted(reports, key=lambda report: (-report["score"], report["source"]))


def discover_production_rust(kernel_root: Path) -> list[Path]:
    """Return Rust modules from the executable tree, excluding verifier artifacts."""
    return sorted(
        path for path in kernel_root.rglob("*.rs")
        if not _NON_PRODUCTION_PARTS.intersection(path.relative_to(kernel_root).parts)
        and not any(part.startswith(("verus_", "refinedrust_"))
                    for part in path.relative_to(kernel_root).parts)
    )
