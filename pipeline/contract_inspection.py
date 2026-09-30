# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Read-only Java/JML surface inspection; no proof or review authority."""
from dataclasses import asdict, dataclass
from collections import Counter
import hashlib
from pathlib import Path

from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .java_contracts import contract_surface, has_reviewed_contract, surface_differences
from .jml_io import _STATEMENT_PREFIX
from .workflow_contracts import WorkflowContext


CONTRACT_LIMITS = {"max_input_bytes": 1024 * 1024, "max_input_files": 2, "max_path_depth": 32}


def _clause_inventory(surface: dict, role: str) -> dict:
    """Count parser-observed syntax, never effective obligations or adequacy."""
    members = []
    for kind, signatures in (("method", surface["methods"]), ("constructor", surface["constructors"])):
        for signature in signatures:
            clauses = surface["clauses"]["members"][signature]
            keywords = Counter()
            for clause in clauses:
                match = _STATEMENT_PREFIX.match(clause)
                # Retain unfamiliar statements rather than silently counting
                # a header or future syntax as a precondition/postcondition.
                keywords[match.group(1).lower() if match else "other"] += 1
            token = signature.replace("~", "~0").replace("/", "~1")
            members.append({"kind": kind, "signature": signature,
                            "clauses_pointer": f"/surfaces/{role}/clauses/members/{token}",
                            "clause_count": len(clauses), "keywords": dict(sorted(keywords.items()))})
    return {"scope": "explicit-parser-observed-member-clauses-only",
            "input_pointer": f"/inputs/{role}", "adequacy": "NOT_ASSESSED",
            "effective_contracts": "NOT_ASSESSED", "member_count": len(members),
            "members_without_explicit_clauses": sum(item["clause_count"] == 0 for item in members),
            "members": members,
            "limitations": [
                "Absence of explicit member clauses is not absence of an effective contract or a demonstrated defect.",
                "Inherited contracts, specification defaults, implicit constructors and generated members are not inventoried.",
                "Class clauses, annotations and proof-trust data remain in surfaces; counts do not measure requirement satisfaction or adequacy.",
            ]}


def _surface_review_changes(source: dict, candidate: dict) -> list[dict]:
    """Locate structural changes, not logical implications between contracts.

    Lists remain atomic: order and duplicate clauses can matter, and matching
    their elements would imply a correspondence this parser does not establish.
    Pointers address this result's captured surfaces, never live source lines.
    """
    categories = {"class": "PUBLIC_API", "methods": "PUBLIC_API",
                  "constructors": "PUBLIC_API", "fields": "PUBLIC_API",
                  "context": "SEMANTIC_CONTEXT", "clauses": "CONTRACT_CLAUSES",
                  "semantic_modifiers": "SEMANTIC_MODIFIERS",
                  "java_annotations": "JAVA_ANNOTATIONS", "proof_trust": "PROOF_TRUST",
                  "private_assumptions": "PROOF_TRUST"}
    changes = []

    def visit(before, after, path, before_present=True, after_present=True):
        if before_present and after_present and before == after:
            return
        if before_present and after_present and isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(before.keys() | after.keys()):
                visit(before.get(key), after.get(key), (*path, key), key in before, key in after)
            return
        pointer = "/" + "/".join(key.replace("~", "~0").replace("/", "~1") for key in path)
        change = {"category": categories.get(path[0], "OTHER_SURFACE"),
                  "kind": "ADDED" if not before_present else "REMOVED" if not after_present else "MODIFIED"}
        for role, value, present in (("source", before, before_present), ("candidate", after, after_present)):
            change[role] = {"input_pointer": f"/inputs/{role}", "present": present,
                            "surface_pointer": f"/surfaces/{role}{pointer}" if present else None,
                            "value": value}
        changes.append(change)

    visit(source, candidate, ())
    return changes


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
              "inputs": {}, "surfaces": {}, "contract_statements_present": {}, "clause_inventory": {},
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
            result["clause_inventory"][role] = _clause_inventory(surface, role)
        if request.operation == "diff":
            differences = surface_differences(result["surfaces"]["source"], result["surfaces"]["candidate"])
            result["comparison"] = {"scope": "supported-public-contract-surface-only",
                                    "surface_equal": not differences, "differences": differences,
                                    "review_changes": _surface_review_changes(
                                        result["surfaces"]["source"], result["surfaces"]["candidate"])}
        result.update(status="CONTRACT_COMPARED" if request.operation == "diff" else "CONTRACT_EXTRACTED",
                      request_satisfied=True)
    except (ValueError, OSError, RecursionError, TypeError) as exc:
        result.update(code=getattr(exc, "code", "INVALID_INPUT"), message=str(exc))
    return result
