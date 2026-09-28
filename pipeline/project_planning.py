# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded project metadata and input identities; never execution authority."""
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re

from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .capability_discovery import CapabilityDiscoveryRequest, discover_capabilities
from .workflow_contracts import WorkflowContext


PROJECT_SCHEMA = "formalspecgen-project-v1"
PROJECT_LIMITS = {"max_input_bytes": 4 * 1024**2, "max_input_files": 128,
                  "max_path_depth": 32, "max_targets": 64, "max_steps": 128}


@dataclass(frozen=True)
class ProjectWorkflowRequest:
    manifest: str
    operation: str = "validate"
    target: str | None = None

    def __post_init__(self):
        if not isinstance(self.manifest, str) or not self.manifest or "\0" in self.manifest:
            raise ValueError("manifest must be a nonempty path")
        if not isinstance(self.operation, str) or self.operation not in {"validate", "plan"}:
            raise ValueError("operation must be validate or plan")
        if self.target is not None:
            _identifier(self.target)

    def required_effects(self):
        return ("workspace_read",)

    def as_dict(self):
        return asdict(self)


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("identifiers must be 1-128 simple letters, digits, dots, dashes or underscores")
    return value


def _fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError("missing or unknown manifest fields")


def _list(value, maximum, *, nonempty=False):
    if not isinstance(value, list) or len(value) > maximum or (nonempty and not value):
        raise ValueError("invalid or excessive manifest list")
    return value


def _relative(value):
    if (not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value
            or "\\" in value or value.startswith("~")):
        raise ValueError("manifest paths must be explicit relative paths")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("manifest paths must remain under the manifest directory")
    return path.as_posix()


def _decode(content):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON field")
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError("nonfinite JSON number")
    return json.loads(content, object_pairs_hook=pairs, parse_constant=nonfinite)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def inspect_project(request: ProjectWorkflowRequest, context: WorkflowContext) -> dict:
    """Validate declarations and capture inputs; plan only registry-level steps.

    Paths are relative to the manifest directory within the caller's authorized
    workspace. Manifest policy fields are requests, never changes to context.
    """
    context.require("workspace_read")
    result = {"schema": "formalspecgen-project-result-v1", "request": request.as_dict(),
              "status": "PROJECT_INVALID", "request_satisfied": False, "claim": "NO_PROOF",
              "invocation_authorized": False, "readiness": "NOT_ASSESSED",
              "assurance": "NOT_ASSESSED", "contract_approval": "NOT_ASSESSED",
              "inputs": [], "findings": [], "targets": [], "steps": [],
              "limitations": [
                  "Static dependency and registry-profile planning, not an executable or authorized plan.",
                  "No tool probes, builds, providers, plugins, verification, or publication run.",
                  "Contracts are caller-declared inputs; their review status is not authenticated.",
                  "Profile compatibility does not validate invocation arguments or supported source fragments.",
                  "Requested policy is not an authority grant, budget reservation, or assurance assessment.",
                  "Only explicit selected inputs are captured; no transitive import or build discovery.",
              ]}
    try:
        limits = {}
        for key, ceiling in PROJECT_LIMITS.items():
            value = context.resource_budget.get(key, ceiling)
            if type(value) is not int or value <= 0:
                raise ValueError("project capture limits must be positive integers")
            limits[key] = min(value, ceiling)
        child = WorkflowContext(context.interface, context.authority, context.workspace_root,
                                context.required_effects, context.output_root, limits)
        budget = CaptureBudget(limits["max_input_bytes"], limits["max_input_files"])
        captured = {}

        def read(value, role):
            _, relative = input_path(value, child)
            key = relative.as_posix()
            if key not in captured:
                with input_directory(relative, child) as directory:
                    data = capture(relative.name, directory, child, budget)
                captured[key] = data
                result["inputs"].append({"path": key, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(), "roles": []})
            entry = next(item for item in result["inputs"] if item["path"] == key)
            if role not in entry["roles"]:
                entry["roles"].append(role)
            return captured[key], relative

        content, manifest_path = read(request.manifest, "manifest")
        result["request"]["manifest"] = manifest_path.as_posix()
        result["manifest_sha256"] = hashlib.sha256(content).hexdigest()
        document = _decode(content)
        _fields(document, ("schema", "targets"), ("policy",))
        if document["schema"] != PROJECT_SCHEMA:
            raise ValueError("unsupported project schema")
        policy = document.get("policy", {})
        _fields(policy, (), ("output_root", "budgets", "required_assurance"))
        if "output_root" in policy:
            _relative(policy["output_root"])
        if "required_assurance" in policy:
            _identifier(policy["required_assurance"])
        budgets = policy.get("budgets", {})
        _fields(budgets, (), ("max_execution_seconds", "max_provider_requests", "max_input_bytes"))
        if any(type(v) is not int or v <= 0 or v > 2**63 - 1 for v in budgets.values()):
            raise ValueError("requested budgets must be bounded positive integers")
        result["requested_policy"] = policy
        targets = {}
        count = 0
        for target in _list(document["targets"], limits["max_targets"], nonempty=True):
            _fields(target, ("name", "sources", "workflows"), ("contracts", "depends_on"))
            name = _identifier(target["name"])
            if name in targets:
                raise ValueError("duplicate target name")
            for field in ("sources", "contracts", "depends_on"):
                values = _list(target.get(field, []), limits["max_input_files"], nonempty=field == "sources")
                normalized = [(_identifier(v) if field == "depends_on" else _relative(v)) for v in values]
                if len(set(normalized)) != len(normalized):
                    raise ValueError("duplicate target input or dependency")
                target[field] = normalized
            for workflow in _list(target["workflows"], limits["max_steps"], nonempty=True):
                _fields(workflow, ("capability", "profile"))
                _identifier(workflow["capability"])
                _identifier(workflow["profile"])
                count += 1
            targets[name] = target
        if count > limits["max_steps"]:
            raise ValueError("aggregate workflow step limit exceeded")
        order, active, visited = [], set(), set()

        def visit(name):
            if name not in targets:
                raise ValueError("unknown target dependency")
            if name in active:
                raise ValueError("cyclic target dependency")
            if name in visited:
                return
            active.add(name)
            for dependency in targets[name]["depends_on"]:
                visit(dependency)
            active.remove(name)
            visited.add(name)
            order.append(name)

        # Validate even unselected dependency edges; do not partially accept a
        # malformed project just because the requested target avoids the cycle.
        for name in targets:
            visit(name)
        if request.target is not None:
            order, active, visited = [], set(), set()
            visit(request.target)
        result["unselected_targets"] = [name for name in targets if name not in order]
        registry = discover_capabilities(CapabilityDiscoveryRequest(), context)
        result["registry_sha256"] = registry["registry_sha256"]
        result["policy_version"] = registry["policy_version"]
        entries = {item["name"]: item for item in registry["capabilities"]}
        for name in order:
            target = targets[name]
            result["targets"].append(name)
            for field in ("sources", "contracts"):
                for source in target[field]:
                    read((manifest_path.parent / source).as_posix(), f"{name}:{field}")
            if not target["contracts"]:
                result["findings"].append({"target": name, "code": "NO_CONTRACT_INPUTS", "blocking": False})
            for workflow in target["workflows"]:
                entry = entries.get(workflow["capability"])
                profiles = [] if entry is None else [p for p in entry["profiles"] if p["name"] == workflow["profile"]]
                available = bool(entry and entry["strict_mcp_exposed"] and len(profiles) == 1)
                step = {"target": name, **workflow, "profile_available": available,
                        "depends_on": target["depends_on"], "invocation_authorized": False,
                        "profile_definition": profiles[0] if available else None,
                        "claim_boundary": entry["claim_boundary"] if entry else None}
                if not available:
                    result["findings"].append({"target": name, "capability": workflow["capability"],
                                               "code": "PROFILE_UNAVAILABLE", "blocking": True})
                if request.operation == "plan":
                    result["steps"].append(step)
        result["inputs_sha256"] = _digest(result["inputs"])
        blocked = any(finding["blocking"] for finding in result["findings"])
        result.update(status="PROJECT_BLOCKED" if blocked else (
            "PROJECT_PLANNED" if request.operation == "plan" else "PROJECT_VALIDATED"),
            request_satisfied=not blocked)
    except (ValueError, OSError, RecursionError, TypeError) as exc:
        result.update(code=getattr(exc, "code", "INVALID_PROJECT"), message=str(exc))
    return result
