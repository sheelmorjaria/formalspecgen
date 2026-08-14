"""Preflight checks for Java lock/TLA lock-protocol correspondence."""
from __future__ import annotations

import re


def check_lock_correspondence(java_sources: dict[str, str], tla_model: str) -> dict:
    synchronized = sorted(name for name, source in java_sources.items()
                          if re.search(r"\bsynchronized\b", source))
    has_protocol = bool(re.search(r"\b(?:Lock|lock_protocol|Acquire|Release)\b", tla_model))
    if not synchronized:
        return {"status": "LOCK_CORRESPONDENCE_MISSING", "claim": "NO_PROOF",
                "message": "No synchronized Java region was found"}
    if not has_protocol:
        return {"status": "LOCK_PROTOCOL_MODEL_MISSING", "claim": "NO_PROOF"}
    return {"status": "LOCK_CORRESPONDENCE_READY", "claim": "NO_PROOF",
            "synchronized_sources": synchronized,
            "concurrent_linearizability_proved": False,
            "proof_obligations": ["lock acquisition order", "release on exceptional paths",
                                   "linearization point correspondence"]}
