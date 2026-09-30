# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Read-only Java/JML surface inspection; no proof or review authority."""
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path

from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .java_contracts import contract_surface, has_reviewed_contract, surface_differences
from .workflow_contracts import WorkflowContext


CONTRACT_LIMITS = {"max_input_bytes": 1024 * 1024, "max_input_files": 2, "max_path_depth": 32}


@dataclass(frozen=True)
class ContractInspectionRequest:
    source: str
    operation: str = "extract"
    candidate: str | None = None

    def __post_init__(self):
        if not isinstance(self.operation, str) or self.operation not in {"extract", "diff"}:
            raise ValueError("contract operation must be extract or diff")
        for name in ("source", "candidate"):
            value = getattr(self, name)
            if name == "candidate" and value is None:
                continue
            if not isinstance(value, str) or not value or "\0" in value:
                raise ValueError(f"{name} must be a nonempty path")
            if Path(value).suffix.lower() not in {".java", ".jml"}:
                raise ValueError("contract inspection supports only Java/JML source files")
        if (self.operation == "diff") != (self.candidate is not None):
            raise ValueError("candidate is required only for diff")

    def required_effects(self):
        return ("workspace_read",)

    def as_dict(self):
        return asdict(self)


def inspect_contract(request: ContractInspectionRequest, context: WorkflowContext) -> dict:
    context.require("workspace_read")
    result = {"schema": "formalspecgen-contract-inspection-v1", "request": request.as_dict(),
              "status": "CONTRACT_INVALID", "request_satisfied": False, "claim": "NO_PROOF",
              "inputs": {}, "surfaces": {}, "contract_statements_present": {},
              "review_status": "NOT_ASSESSED", "semantic_equivalence_proved": False,
              "behavior_equivalence_proved": False,
              "limitations": [
                  "Supported public/protected Java/JML surface only; not a full language semantic analysis.",
                  "Private implementation details and ordinary private contracts are excluded; parser-recognized proof-trust assumptions are retained.",
                  "Differences are structural data, not proof of stronger/weaker contracts or behavioral equivalence.",
                  "No verification, dependency resolution, provider access, publication, or authenticated human review occurs.",
                  "Surface agreement does not accept a refactor, establish adequate requirements, or authorize integration.",
              ]}
    try:
        limits = {}
        for name, ceiling in CONTRACT_LIMITS.items():
            value = context.resource_budget.get(name, ceiling)
            if type(value) is not int or value <= 0:
                raise ValueError("contract capture limits must be positive integers")
            limits[name] = min(value, ceiling)
        child = WorkflowContext(context.interface, context.authority, context.workspace_root,
                                context.required_effects, context.output_root, limits)
        budget = CaptureBudget(limits["max_input_bytes"], limits["max_input_files"])
        captured = {}
        parsed = {}
        for role, value in (("source", request.source), ("candidate", request.candidate)):
            if value is None:
                continue
            _, relative = input_path(value, child)
            key = relative.as_posix()
            result["request"][role] = key
            if key not in captured:
                with input_directory(relative, child) as directory:
                    captured[key] = capture(relative.name, directory, child, budget)
            content = captured[key]
            result["inputs"][role] = {"path": key, "size": len(content),
                                      "sha256": hashlib.sha256(content).hexdigest()}
            if key not in parsed:
                parsed[key] = contract_surface(content.decode("utf-8"), public_only=True)
            surface = parsed[key]
            result["surfaces"][role] = surface
            if surface["parse_errors"] or not surface["class"]:
                result.update(status="CONTRACT_UNSUPPORTED", code="UNSUPPORTED_CONTRACT_SYNTAX",
                              message="No supported class surface, or parser-reported unsupported syntax.")
                return result
            # The historical parser helper name does not authenticate review.
            result["contract_statements_present"][role] = has_reviewed_contract(surface)
        if request.operation == "diff":
            differences = surface_differences(result["surfaces"]["source"], result["surfaces"]["candidate"])
            result["comparison"] = {"scope": "supported-public-contract-surface-only",
                                    "surface_equal": not differences, "differences": differences}
        result.update(status="CONTRACT_COMPARED" if request.operation == "diff" else "CONTRACT_EXTRACTED",
                      request_satisfied=True)
    except (ValueError, OSError, RecursionError, TypeError) as exc:
        result.update(code=getattr(exc, "code", "INVALID_INPUT"), message=str(exc))
    return result
