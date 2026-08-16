"""Shared apply-refactor core used by the CLI and the MCP façade."""
from __future__ import annotations

from pathlib import Path

_MULTIFILE_PATTERNS = {"factory-method", "state", "decorator", "facade", "null-object", "strategy"}


def apply_refactor(source: str | Path, inspection: str | Path, pattern: str,
                   method: str, out: str | Path) -> dict:
    """Apply one hash-bound refactor profile and immediately run its proof gate.

    Returns the transform result unchanged when the profile fails closed; on a
    successful transformation the combined verdict embeds both the transform
    evidence and the (single-file or multifile) gate result.
    """
    from .deterministic_refactor import (
        extract_decorator_from_inspection,
        extract_factory_from_inspection,
        extract_facade_from_inspection,
        extract_method_from_inspection,
        extract_null_object_from_inspection,
        extract_state_from_inspection,
    )
    from .refactor_gate import (
        verify_contract_preserving_refactor,
        verify_multifile_contract_refactor,
    )
    from .strategy_refactor import extract_strategy_from_inspection
    transformed = (extract_strategy_from_inspection(source, inspection, method)
                   if pattern == "strategy" else
                   extract_facade_from_inspection(source, inspection)
                   if pattern == "facade" else
                   extract_decorator_from_inspection(source, inspection)
                   if pattern == "decorator" else
                   extract_factory_from_inspection(source, inspection, method)
                   if pattern == "factory-method" else
                   extract_state_from_inspection(source, inspection, method)
                   if pattern == "state" else
                   extract_null_object_from_inspection(source, inspection)
                   if pattern == "null-object" else
                   extract_method_from_inspection(source, inspection, method))
    if transformed["status"] != "TRANSFORMED":
        return transformed
    destination = Path(out)
    if pattern in _MULTIFILE_PATTERNS:
        destination.mkdir(parents=True, exist_ok=True)
        files = transformed.pop("files")
        for name, content in files.items():
            (destination / name).write_text(content, encoding="utf-8")
        proof = verify_multifile_contract_refactor(source, destination)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(transformed.pop("source"), encoding="utf-8")
        proof = verify_contract_preserving_refactor(source, destination)
    return {"status": "VERIFIED" if proof["status"] == "VERIFIED" else "FAIL",
            "claim": proof.get("claim", "NO_PROOF"),
            "transformation": transformed, "verification": proof,
            "automated_refactor_applied": True,
            "behavior_equivalence_proved": False,
            "refactor_verified": False}
