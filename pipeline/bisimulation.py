"""Fail-closed preflight checks for scoped behavioral-equivalence work."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_PUBLIC_METHOD = re.compile(r"\bpublic\s+(?:static\s+)?[A-Za-z_$][\w$<>\[\]]*\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")


def verify_bisimulation_inputs(baseline: str | Path, refactored: str | Path,
                               mapping: str | Path) -> dict:
    """Validate a state mapping and bind source hashes without claiming equivalence."""
    try:
        baseline_path, refactored_path = Path(baseline), Path(refactored)
        mapping_value = json.loads(Path(mapping).read_text(encoding="utf-8"))
        baseline_text = baseline_path.read_text(encoding="utf-8")
        if refactored_path.is_dir():
            sources = sorted(str(path) for path in refactored_path.glob("*.java"))
            refactored_hash = hashlib.sha256("".join(
                Path(path).read_bytes().decode("utf-8") for path in sources).encode()).hexdigest()
        else:
            sources = [str(refactored_path)]
            refactored_hash = hashlib.sha256(refactored_path.read_bytes()).hexdigest()
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        return {"status": "BISIMULATION_INPUT_INVALID", "claim": "NO_PROOF", "message": str(exc)}
    if not isinstance(mapping_value, dict) or not mapping_value:
        return {"status": "BISIMULATION_MAPPING_INVALID", "claim": "NO_PROOF"}
    if any(not isinstance(key, str) or not _IDENTIFIER.fullmatch(value)
           for key, value in mapping_value.items() if isinstance(value, str)):
        return {"status": "BISIMULATION_MAPPING_INVALID", "claim": "NO_PROOF"}
    if any(not isinstance(key, str) or not isinstance(value, str) or
           not _IDENTIFIER.fullmatch(value) for key, value in mapping_value.items()):
        return {"status": "BISIMULATION_MAPPING_INVALID", "claim": "NO_PROOF"}
    refactored_text = "\n".join(Path(path).read_text(encoding="utf-8") for path in sources)
    state_types = set(re.findall(r"\bclass\s+([A-Za-z_$][A-Za-z0-9_$]*)", refactored_text))
    missing = sorted(set(mapping_value.values()) - state_types)
    if missing:
        return {"status": "BISIMULATION_STATE_UNRESOLVED", "claim": "NO_PROOF",
                "missing_states": missing}
    baseline_surface = sorted(_PUBLIC_METHOD.findall(baseline_text))
    refactored_surface = sorted(_PUBLIC_METHOD.findall(refactored_text))
    if baseline_surface != refactored_surface:
        return {"status": "BISIMULATION_SURFACE_MISMATCH", "claim": "NO_PROOF",
                "contract_surface_preserved": False,
                "baseline_public_surface": baseline_surface,
                "refactored_public_surface": refactored_surface,
                "mapping": mapping_value}
    return {"status": "BISIMULATION_PREFLIGHT_READY", "claim": "NO_PROOF",
            "behavior_equivalence_proved": False, "heap_topology_equivalence_proved": False,
            "contract_surface_preserved": baseline_surface == refactored_surface,
            "baseline_public_surface": baseline_surface,
            "refactored_public_surface": refactored_surface,
            "mapping": mapping_value,
            "baseline_sha256": hashlib.sha256(baseline_text.encode()).hexdigest(),
            "refactored_sha256": refactored_hash, "refactored_sources": sources}
