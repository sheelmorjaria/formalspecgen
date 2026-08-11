# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic Architecture Decision Record generation from verified artifacts."""
import re
from datetime import date

from .architecture import Architecture, parse_architecture, lint_architecture


def generate_adr(value: Architecture | dict | str, verification: dict | None = None,
                 number: int = 1) -> str:
    architecture = value if isinstance(value, Architecture) else parse_architecture(value)
    lint = lint_architecture(architecture)
    blocking = [item for item in lint if item["severity"] == "error"]
    status = "Accepted" if not blocking and (verification or {}).get("status") == "VERIFIED" else "Proposed"
    title = re.sub(r"[^A-Za-z0-9 ]+", "", architecture.name).strip() or "System Architecture"
    layers = {layer: [component.name for component in architecture.components if component.layer == layer]
              for layer in ("entities", "use_cases", "adapters", "infrastructure")}
    abstractions = [(component.name, dependency.target) for component in architecture.components
                    for dependency in component.dependencies if dependency.abstraction]
    role_splits = [component.name for component in architecture.components
                   if re.search(r"(?:Reader|Writer|Read|Write|Port|Gateway)$", component.name)]
    security = [flow for flow in architecture.data_flows
                if flow.authenticated or flow.authorized or flow.encrypted or flow.sanitizer_operation]
    lines = [f"# ADR-{number:04d}: {title}", "", f"- Status: {status}",
             f"- Date: {date.today().isoformat()}", "", "## Context", "",
             architecture.description or "The system requires a layered, contract-verifiable architecture.", "",
             "## Decision", "",
             "Use a Clean Architecture dependency structure with policy owned by the inner layers and implementations in outer layers.", ""]
    for layer, components in layers.items():
        if components:
            lines.append(f"- **{layer.replace('_', ' ').title()}:** " + ", ".join(components))
    if abstractions:
        lines.append("- Dependencies cross layers through declared abstractions: " +
                     ", ".join(f"{source} → {target}" for source, target in abstractions) + ".")
    if role_splits:
        lines.append("- Role-specific interfaces support Interface Segregation: " + ", ".join(role_splits) + ".")
    if architecture.invariants:
        lines.append("- Architectural safety invariants: " + "; ".join(architecture.invariants) + ".")
    if security:
        lines.append(f"- {len(security)} trust-boundary flow(s) declare explicit STRIDE mitigations.")
    lines.extend(["", "## Verification evidence", ""])
    tlc = verification or {}
    lines.append(f"- TLA+/TLC status: `{tlc.get('status', 'NOT_RUN')}`.")
    lines.append(f"- Architecture linter: {len(blocking)} blocking and {len(lint) - len(blocking)} advisory finding(s).")
    lines.append("- Interface and orchestrator contracts are checked separately by OpenJML during scaffolding.")
    lines.extend(["", "## Consequences", "",
                  "- Inner policy code does not depend directly on infrastructure implementations.",
                  "- Component interaction order is represented as use-case contract composition.",
                  "- Architecture changes require re-running TLC, SOLID/STRIDE linting, and affected composition proofs."])
    if blocking:
        lines.extend(["", "## Unresolved blocking findings", ""])
        lines.extend(f"- `{item['code']}`: {item['message']}" for item in blocking)
    if architecture.assumptions:
        lines.extend(["", "## Assumptions", ""])
        lines.extend(f"- {assumption}" for assumption in architecture.assumptions)
    return "\n".join(lines) + "\n"
