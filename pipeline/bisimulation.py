"""Fail-closed preflight checks for scoped behavioral-equivalence work."""
from __future__ import annotations

import re
from pathlib import Path


_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_PUBLIC_METHOD = re.compile(r"\bpublic\s+(?:static\s+)?[A-Za-z_$][\w$<>\[\]]*\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
_PUBLIC_PREFIX = re.compile(r"\bpublic\s+(?:static\s+)?[A-Za-z_$][\w$<>\[\]]*\s+([A-Za-z_$][\w$]*)\s*\(")


def public_surface(text: str) -> list[tuple[str, str]]:
    """Legacy lexical matches without repeatedly scanning unclosed parameter tails."""
    result = []
    cursor = 0
    for match in _PUBLIC_PREFIX.finditer(text):
        if match.start() < cursor:
            continue
        end = text.find(")", match.end())
        if end < 0:
            break
        result.append((match[1], text[match.end():end]))
        cursor = end + 1
    return sorted(result)


def check_bisimulation_sources(baseline_text: str, refactored_text: str, mapping_value) -> dict:
    """Pure mapping/API preflight over captured text, not Java semantic analysis."""
    if not isinstance(mapping_value, dict) or not mapping_value or any(
            not isinstance(key, str) or not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
            for key, value in mapping_value.items()):
        return {"status": "BISIMULATION_MAPPING_INVALID", "claim": "NO_PROOF"}
    state_types = set(re.findall(r"\bclass\s+([A-Za-z_$][A-Za-z0-9_$]*)", refactored_text))
    missing = sorted(set(mapping_value.values()) - state_types)
    if missing:
        return {"status": "BISIMULATION_STATE_UNRESOLVED", "claim": "NO_PROOF", "missing_states": missing}
    baseline_surface = public_surface(baseline_text)
    refactored_surface = public_surface(refactored_text)
    preserved = baseline_surface == refactored_surface
    return {"status": "BISIMULATION_PREFLIGHT_READY" if preserved else "BISIMULATION_SURFACE_MISMATCH",
            "claim": "NO_PROOF", "contract_surface_preserved": preserved,
            "baseline_public_surface": baseline_surface, "refactored_public_surface": refactored_surface,
            "mapping": mapping_value}


def verify_bisimulation_inputs(baseline: str | Path, refactored: str | Path,
                               mapping: str | Path) -> dict:
    """Compatibility entry point through the shared bounded preflight service."""
    import os
    from .bisimulation_workflow import BISIMULATION_BUDGET, BisimulationWorkflowRequest, run_bisimulation_workflow
    from .workflow_contracts import WorkflowContext
    request = BisimulationWorkflowRequest(str(baseline), str(refactored), str(mapping))
    root = Path(os.path.commonpath([Path(value).parent for value in
                                  (request.baseline, request.refactored, request.mapping)]))
    return run_bisimulation_workflow(request, WorkflowContext.for_cli(
        request.required_effects(), workspace_root=root, resource_budget=BISIMULATION_BUDGET))
