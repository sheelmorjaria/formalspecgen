# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Non-evidentiary M87 scan for exact production Rust atomic transitions."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path


_ATOMIC = re.compile(
    r"\bAtomic(?:Bool|U8|U16|U32|U64|Usize|I8|I16|I32|I64|Isize|Ptr)\b")
_OPERATION = re.compile(
    r"\.(?:load|store|swap|compare_exchange(?:_weak)?|fetch_(?:add|sub|and|or|xor))\s*\(")
_ORDERING = re.compile(r"\bOrdering::(Relaxed|Acquire|Release|AcqRel|SeqCst)\b")
_EXCLUDED = {"target", "proofs", "refinement", "refinedrust_smoke",
             "verus_allocator", "verus_smoke", "verus_virtio"}


def scan_atomic_production(root: Path) -> dict:
    """Find atomic operations without treating discovery as correctness evidence."""
    sources = []
    for path in sorted(root.rglob("*.rs")):
        relative = path.relative_to(root)
        if _EXCLUDED.intersection(relative.parts):
            continue
        text = path.read_text(encoding="utf-8")
        atomics = sorted(set(_ATOMIC.findall(text)))
        operations = sorted(set(_OPERATION.findall(text)))
        orderings = sorted(set(_ORDERING.findall(text)))
        sources.append({
            "source": path.as_posix(),
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "atomic_types": atomics,
            "atomic_operations": operations,
            "memory_orderings": orderings,
            "eligible": bool(atomics and operations and orderings),
        })
    eligible = [item for item in sources if item["eligible"]]
    return {
        "status": "ATOMIC_PRODUCTION_CANDIDATE_FOUND" if eligible
                  else "PARKED_NO_PRODUCTION_ATOMIC_TRANSITION",
        "claim": "NO_PROOF",
        "scanned_source_count": len(sources),
        "eligible_candidates": eligible,
        "sources": sources,
    }
