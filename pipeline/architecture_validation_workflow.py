# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded, model-only architecture validation shared by CLI and MCP."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

from .architecture_tla_renderer import render_unified_architecture
from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .execution import StrictSandboxExecutor
from .isolated_tlc import TlcModelRequest, run_isolated_tlc
from .mcp_artifacts import MCPArtifactError, publish_new_artifacts
from .mcp_policy import MCPPolicyViolation
from .multistage_evidence import publish_controlled_multistage_evidence
from .staged_architecture import UnifiedArchitecture
from .workflow_contracts import WORKFLOW_CONTRACT_SCHEMA, WorkflowContext, bind_workflow_result


ARCHITECTURE_BUDGET = {"max_input_bytes": 4 * 1024**2, "max_input_files": 1,
    "max_path_depth": 32, "max_json_nodes": 16384, "max_json_depth": 32,
    "max_state_space": 1000000, "max_generated_bytes": 1024**2,
    "max_execution_seconds": 120, "max_output_bytes": 1024**2,
    "max_result_bytes": 16 * 1024**2}


@dataclass(frozen=True)
class ArchitectureValidationRequest:
    artifact_path: str
    timeout: int = 120
    result_export: str | None = None

    def __post_init__(self):
        if not isinstance(self.artifact_path, str) or not self.artifact_path or "\0" in self.artifact_path:
            raise ValueError("artifact_path must be a nonempty path")
        object.__setattr__(self, "artifact_path", str(Path(self.artifact_path).expanduser().absolute()))
        if type(self.timeout) is not int or self.timeout <= 0:
            raise ValueError("timeout must be a positive integer")
        if self.result_export is not None and (not isinstance(self.result_export, str)
                or not self.result_export or "\0" in self.result_export):
            raise ValueError("result_export must be a nonempty path or null")

    def required_effects(self):
        return ("workspace_read", "external_execution", "evidence_publication", "workspace_write_new")

    def as_dict(self):
        return {"schema": WORKFLOW_CONTRACT_SCHEMA, "workflow": "validate-architecture", **asdict(self)}


def _decode(content, limits):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate architecture JSON key")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("nonfinite architecture JSON value")
    value = json.loads(content.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > limits["max_json_nodes"] or depth > limits["max_json_depth"]:
            raise ValueError("architecture JSON structure allowance exceeded")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        for child in children:
            if visited + len(pending) + 1 > limits["max_json_nodes"]:
                raise ValueError("architecture JSON node allowance exceeded")
            pending.append((child, depth + 1))
    return value


def _model_scope(architecture, maximum):
    # The legacy renderer flattens state/actions and does not lower domains,
    # operation contracts, dependencies or use-case ordering. Do not infer them.
    variables, actions, bounds, size = set(), set(), {}, 1
    for component in architecture.components:
        if component.domain:
            raise ValueError("reviewed-domain references require separate composition lowering")
        for state in component.state_variables:
            if state.name in variables:
                raise ValueError("flattened state names must be unique")
            variables.add(state.name)
            if state.type == "int" and state.bound is None:
                raise ValueError("integer state requires finite bounds")
            count = state.bound[1] - state.bound[0] + 1 if state.type == "int" else 2
            if count > maximum // size:
                raise ValueError("architecture state-space allowance exceeded")
            size *= count
            bounds[state.name] = list(state.bound) if state.type == "int" else [False, True]
        for transition in component.transitions:
            if transition.operation_name in actions:
                raise ValueError("flattened action names must be unique")
            actions.add(transition.operation_name)
    if variables & actions or (variables | actions) & {"Init", "Next", "TypeOK", "Spec"}:
        raise ValueError("flattened symbols collide with generated model definitions")
    return {"state_space_upper_bound": size, "bounds": bounds, "checked_invariants": ["TypeOK"],
            "atomic_actions": sorted(actions)}


def run_architecture_validation(request: ArchitectureValidationRequest, context: WorkflowContext,
        *, executor=None) -> dict:
    result = {"status": "ARCHITECTURE_INVALID", "claim": "NO_PROOF", "request_satisfied": False,
        "inputs": [], "generated_models": {}, "model_scope": {}, "tlc": None,
        "execution_stages": [], "publication": {"status": "NOT_ATTEMPTED"},
        "claim_limits": {"source_correspondence_proved": False, "behavior_equivalence_proved": False,
            "scope": "generated finite state model: TypeOK and default TLC deadlock checking",
            "not_established": ["operation contracts", "use-case ordering", "source implementation",
                                "external component behavior", "liveness", "specification adequacy"]}}
    export, prepared, published_size = request.result_export, {}, 0
    observed = []
    class Recorder:
        def execute(self, invocation):
            context.require("external_execution")
            observation = (executor or StrictSandboxExecutor()).execute(invocation)
            observed.append(observation.as_dict())
            return observation
    limits = {name: min(context.resource_budget.get(name, limit), limit) for name, limit in ARCHITECTURE_BUDGET.items()}
    bound = lambda: bind_workflow_result(result, request, context.interface, context=context)
    try:
        if any(type(value) is not int or value <= 0 for value in limits.values()):
            raise ValueError("architecture limits must be positive integers")
        for effect in request.required_effects():
            context.require(effect)
        if context.output_root is None:
            raise ValueError("architecture validation requires an output root")
        path, relative = input_path(request.artifact_path, context)
        if export and (Path(export).is_absolute() or ".." in Path(export).parts
                or (context.output_root / export).resolve() == path.resolve()):
            export = None
            raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "export aliases input or escapes output root")
        with input_directory(relative, context) as directory:
            content = capture(relative.name, directory, context, CaptureBudget(limits["max_input_bytes"], 1))
        result["inputs"] = [{"path": relative.as_posix(), "size": len(content),
                             "sha256": hashlib.sha256(content).hexdigest()}]
        architecture = UnifiedArchitecture.model_validate(_decode(content, limits))
        result["model_scope"] = _model_scope(architecture, limits["max_state_space"])
        result["architecture"] = architecture.model_dump(mode="json")
        states = [state for component in architecture.components for state in component.state_variables]
        action_count = sum(len(component.transitions) for component in architecture.components)
        # UNCHANGED lists repeat state names per action. Bound that cross-product
        # before rendering, rather than allocating a large expansion then rejecting it.
        render_allowance = (16 * len(architecture.model_dump_json().encode())
            + sum(len(state.name.encode()) + 2 for state in states) * (action_count + 8)
            + 128 * (len(states) + action_count + 1))
        if render_allowance > limits["max_generated_bytes"]:
            raise ValueError("architecture rendering expansion allowance exceeded")
        # The module filename is controller-selected, not a path or TLA identifier
        # supplied by the caller. The original architecture name remains bound.
        model = architecture.model_copy(update={"name": "Architecture"})
        tla, cfg = render_unified_architecture(model)
        if len(tla.encode()) + len(cfg.encode()) > limits["max_generated_bytes"]:
            raise ValueError("generated architecture model allowance exceeded")
        prepared = {"Architecture.tla": tla, "Architecture.cfg": cfg}
        result["generated_models"] = {name: {"sha256": hashlib.sha256(text.encode()).hexdigest(),
            "size": len(text.encode())} for name, text in prepared.items()}
        result["status"] = "ARCHITECTURE_CHECK_FAILED"
        tlc = run_isolated_tlc(TlcModelRequest("Architecture", tla, cfg, request.timeout),
            context.child(("external_execution",)), executor=Recorder())
        result["tlc"] = tlc
        observations = tlc["execution_observations"]
        result["execution_stages"] = [{"stage": item["tool"], **item} for item in observations]
        # Successful evidence must bind both observed stages to these exact models.
        bound_models = len(observations) == 2 and all(
            item["policy_compliance"] == "ENFORCED" and all(any(
                entry["path"] == name and entry["sha256"] == identity["sha256"]
                and entry["size"] == identity["size"] for entry in item["snapshot_files"])
                for name, identity in result["generated_models"].items()) for item in observations)
        if tlc["model_check_passed"] and bound_models:
            result.update(status="VERIFIED", claim="BOUNDED_ARCHITECTURE_EVIDENCE", request_satisfied=True)
        else:
            result["status"] = "ARCHITECTURE_CHECK_FAILED"
    except (OSError, ValueError, RuntimeError, RecursionError, MCPPolicyViolation) as exc:
        result.update(code=getattr(exc, "code", result["status"]), message=str(exc), request_satisfied=False)
    result["execution_stages"] = [{"stage": item["tool"], **item} for item in observed]
    try:
        result["publication"] = publish_controlled_multistage_evidence(context,
            artifact_prefix="architecture-evidence", max_total_bytes=limits["max_result_bytes"],
            prepared_artifacts=prepared, workflow="validate-architecture", status=result["status"],
            claim=result["claim"], request=request.as_dict(), admission=context.authority.summary(),
            inputs={"sources": result["inputs"], "generated_models": result["generated_models"]},
            stages=result["execution_stages"], semantic_bindings={"model_scope": result["model_scope"],
                "architecture": result.get("architecture"), "tlc": result["tlc"],
                "generated_model_text": prepared,
                "diagnostic": {key: result[key] for key in ("code", "message") if key in result}},
            claim_limits=result["claim_limits"], request_satisfied=result["request_satisfied"])
        published_size = sum(item["size"] for item in result["publication"]["artifacts"].values())
        for name, identity in result["generated_models"].items():
            identity["path"] = next(item["path"] for key, item in result["publication"]["artifacts"].items()
                                    if key.endswith("/" + name))
    except (OSError, ValueError, RuntimeError, MCPPolicyViolation) as exc:
        result.update(status="EVIDENCE_PUBLICATION_FAILED", claim="NO_PROOF", request_satisfied=False,
                      message=str(exc), publication={"status": "FAILED"})
    if export and context.output_root is not None:
        try:
            context.require("workspace_write_new")
            published = publish_new_artifacts(context.output_root, {export: json.dumps(bound(), indent=2) + "\n"},
                context.authority, max_total_bytes=max(0, limits["max_result_bytes"] - published_size))
            result["result_export"] = {"status": "COMMITTED", "artifacts": published}
        except (OSError, ValueError, MCPPolicyViolation) as exc:
            result.update(status="RESULT_EXPORT_FAILED", claim="NO_PROOF", request_satisfied=False,
                code=getattr(exc, "code", "PUBLICATION_FAILED"), message=str(exc), result_export={"status": "FAILED"})
    return bound()
