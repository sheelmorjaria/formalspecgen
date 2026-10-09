# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Permission-carrying V2 domain validation shared by CLI and MCP."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
import re

from .domain_v2 import DomainSpecV2
from .domain_v2_model import (
    MAX_STATE_SPACE, MAX_TRANSITIONS, MAX_WORK_ITEMS, UnsupportedV2Boundary,
    static_deadlock_findings, validate_transitions_and_invariants,
)
from .domain_v2_publication import TlcEvidence, ValidatedEvidence, validated_envelope
from .domain_validation_preparation import (
    DOMAIN_PREPARATION_LIMITS, DomainPreparationRequest, capture_domain_candidate,
    prepare_captured_domain_candidate,
)
from .execution import StrictSandboxExecutor
from .isolated_tlc import run_isolated_tlc
from .mcp_artifacts import MCPArtifactError, publish_new_artifacts
from .mcp_policy import MCPPolicyViolation
from .multistage_evidence import publish_controlled_multistage_evidence
from .workflow_contracts import WORKFLOW_CONTRACT_SCHEMA, WorkflowContext, bind_workflow_result


DOMAIN_VALIDATION_LIMITS = {**DOMAIN_PREPARATION_LIMITS,
    "max_states": MAX_STATE_SPACE, "max_transitions": MAX_TRANSITIONS,
    "max_work_items": MAX_WORK_ITEMS, "max_state_bound_bits": 1024,
    "max_execution_seconds": 120, "max_output_bytes": 1024**2,
    "max_result_bytes": 32 * 1024**2}


@dataclass(frozen=True)
class DomainValidationWorkflowRequest:
    candidate_path: str
    timeout: int = 120
    emit_tla: str | None = None
    result_export: str | None = None
    max_states: int = MAX_STATE_SPACE
    max_transitions: int = MAX_TRANSITIONS
    max_work_items: int = MAX_WORK_ITEMS

    def __post_init__(self):
        DomainPreparationRequest(self.candidate_path)
        if type(self.timeout) is not int or self.timeout <= 0:
            raise ValueError("timeout must be a positive integer")
        for name in ("emit_tla", "result_export"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value or "\0" in value):
                raise ValueError(f"{name} must be a nonempty output path or null")
        for name in ("max_states", "max_transitions", "max_work_items"):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= DOMAIN_VALIDATION_LIMITS[name]:
                raise ValueError(f"{name} must be a positive integer within the service ceiling")

    @classmethod
    def for_candidate(cls, name: str, project_root: str = ".", **options):
        """Map public names to paths without resolving away input symlinks."""
        name = domain_candidate_name(name)
        if not isinstance(project_root, str) or not project_root or "\0" in project_root:
            raise ValueError("project_root must be a nonempty path")
        candidate = Path(project_root).expanduser().absolute() / "domains/candidates" / f"{name}.v2.yaml"
        return cls(str(candidate), **options)

    def required_effects(self):
        return ("workspace_read", "external_execution", "evidence_publication", "workspace_write_new")

    def as_dict(self):
        return {"schema": WORKFLOW_CONTRACT_SCHEMA, "workflow": "validate-domain", **asdict(self)}


def domain_candidate_name(value: str) -> str:
    """Accept a module or displayed candidate basename, never a path."""
    if not isinstance(value, str):
        raise ValueError("domain candidate name must be a string")
    raw = value.strip().lower().replace("-", "_")
    if Path(raw).name != raw:
        raise ValueError("domain candidate must be a module name or basename, not a path")
    for suffix in (".v2.validation.json", ".v2.yaml", ".generated.yaml", ".generated", ".v2", ".yaml"):
        if raw.endswith(suffix):
            raw = raw[:-len(suffix)]
            break
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", raw):
        raise ValueError("domain candidate name must be a safe lower-case identifier")
    return raw


def _output_key(value, source, root):
    path = Path(value)
    if (path.is_absolute() or ".." in path.parts or not path.name
            or (root / path).resolve() == source.resolve()):
        raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "output escapes its root or aliases the candidate")
    return path.as_posix()


def _scope(candidate, max_bits):
    # Preserve the exact finite estimate, including actor state, but never
    # allocate/serialize an arbitrarily large product. This reporting limit is
    # independent of the actual reachable-state traversal limit.
    upper = 1
    for state in candidate.state_variables:
        upper *= (state.bound[1] - state.bound[0] + 1) if state.kind == "int" else 2
        if upper.bit_length() > max_bits:
            raise UnsupportedV2Boundary("state-space estimate exceeds reporting allowance")
    if any(op.failure_semantics == "false_and_stutter" for op in candidate.operations):
        upper *= 3 ** candidate.actors
    if candidate.concurrency is not None and candidate.concurrency.linearization_points is not None:
        upper *= (1 + 4 * len(candidate.operations)) ** candidate.actors
    if upper.bit_length() > max_bits:
        raise UnsupportedV2Boundary("state-space estimate exceeds reporting allowance")
    return {"state_space_upper_bound": upper,
        "actor_count": candidate.actors,
        "state_bounds": {state.name: list(state.bound) if state.kind == "int" else [False, True]
                         for state in candidate.state_variables},
        "bounds": {**{state.name: list(state.bound) if state.kind == "int" else 2
                       for state in candidate.state_variables}, "actors": candidate.actors},
        "execution_assumption": "bounded_async_handler_abstraction"
            if candidate.execution_model == "async_message_passing" else
            "bounded_lock_history_abstraction" if candidate.concurrency is not None else
            "atomic_last_result_abstraction",
        "abstraction_mode": "async_message_passing"
            if candidate.execution_model == "async_message_passing" else
            "lock_protocol" if candidate.concurrency is not None else "atomic_operations"}


def _bound_stages(observed, reported, models):
    return (observed == reported and len(observed) == 2
        and [item["tool"] for item in observed] == ["tlc-provenance", "tlc-model-check"]
        and all(item["policy_compliance"] == "ENFORCED" and all(any(
            entry["path"] == name and entry["sha256"] == identity["sha256"]
            and entry["size"] == identity["size"] for entry in item["snapshot_files"])
            for name, identity in models.items()) for item in observed))


def run_domain_validation(request: DomainValidationWorkflowRequest, context: WorkflowContext,
                          *, executor=None) -> dict:
    result = {"status": "DOMAIN_VALIDATION_FAILED", "claim": "NO_PROOF", "request_satisfied": False,
        "checks_satisfied": False, "failed_gate": "request", "inputs": [], "preparation": None,
        "model_scope": {}, "generated_models": {}, "traversal": None, "tlc": None,
        "execution_stages": [], "model_export": {"status": "NOT_REQUESTED" if request.emit_tla is None else "NOT_ATTEMPTED"},
        "publication": {"status": "NOT_ATTEMPTED"},
        "claim_limits": {"scope": "finite V2 model under declared bounds and execution abstraction",
            "source_correspondence_proved": False, "review_authenticated": False,
            "not_established": ["source correctness", "unbounded behavior", "liveness",
                                "specification adequacy", "human approval or promotion"]}}
    artifacts, model_text, captured_text, observed = {}, {}, None, []
    export, model_keys, used = None, None, 0
    limits = {}
    for name, ceiling in DOMAIN_VALIDATION_LIMITS.items():
        value = context.resource_budget.get(name, ceiling)
        if name in {"max_states", "max_transitions", "max_work_items"} and type(value) is int:
            value = min(value, getattr(request, name))
        limits[name] = min(value, ceiling) if type(value) is int and value >= 0 else 0
    bound = lambda: bind_workflow_result(result, request, context.interface, context=context)
    class Recorder:
        def execute(self, invocation):
            context.require("external_execution")
            observation = (executor or StrictSandboxExecutor()).execute(invocation)
            observed.append(observation.as_dict())
            return observation
    try:
        for name, value in limits.items():
            if value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for effect in request.required_effects():
            context.require(effect)
        if context.output_root is None:
            raise ValueError("domain validation requires an output root")
        source = Path(request.candidate_path).expanduser()
        if not source.is_absolute():
            source = context.workspace_root / source
        if request.result_export is not None:
            export = _output_key(request.result_export, source, context.output_root)
        if request.emit_tla is not None:
            model_keys = (_output_key(request.emit_tla, source, context.output_root),
                _output_key(str(Path(request.emit_tla).with_suffix(".cfg")), source, context.output_root))
            if len(set(model_keys)) != 2 or export in model_keys:
                export = None if export in model_keys else export
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "model and result destinations must be distinct")
        result["failed_gate"] = "capture"
        captured = capture_domain_candidate(DomainPreparationRequest(request.candidate_path),
                                             context.child(("workspace_read",)))
        result["inputs"] = [captured.identity()]
        artifacts["candidate.input"] = captured.source_bytes
        captured_text = base64.b64encode(captured.source_bytes).decode("ascii")
        result["failed_gate"] = "preparation"
        prepared = prepare_captured_domain_candidate(captured)
        summary = prepared.summary()
        result.update(preparation=summary,
                      generated_models={name: dict(identity) for name, identity in summary["generated_models"].items()},
                      candidate_sha256=prepared.candidate_sha256)
        candidate = DomainSpecV2.model_validate_json(prepared.candidate_json)
        model_text = {prepared.model.module_name + ".tla": prepared.model.tla,
                      prepared.model.module_name + ".cfg": prepared.model.cfg}
        artifacts.update(model_text)
        result["model_scope"] = _scope(candidate, limits["max_state_bound_bits"])
        result["failed_gate"] = "static_deadlock"
        findings = static_deadlock_findings(candidate)
        result["static_findings"] = findings
        if findings:
            raise ValueError("; ".join(findings))
        result["failed_gate"] = "bounded_traversal"
        states, transitions = validate_transitions_and_invariants(candidate,
            max_states=limits["max_states"], max_transitions=limits["max_transitions"],
            max_work_items=limits["max_work_items"])
        result["traversal"] = {"status": "PASSED", "reachable_states": states,
                               "reachable_transitions": transitions}
        result["failed_gate"] = "tlc"
        tlc = run_isolated_tlc(replace(prepared.model, timeout_s=request.timeout),
            context.child(("external_execution",)), executor=Recorder())
        result["tlc"] = tlc
        if not tlc["model_check_passed"] or not _bound_stages(
                observed, tlc["execution_observations"], result["generated_models"]):
            raise ValueError("TLC did not establish an enforced check of the captured model")
        evidence = ValidatedEvidence(candidate_sha256=prepared.candidate_sha256,
            generated_tla_sha256=summary["generated_models"][prepared.model.module_name + ".tla"]["sha256"],
            **{name: result["model_scope"][name] for name in (
                "bounds", "state_space_upper_bound", "execution_assumption", "abstraction_mode")},
            reachable_state_count=states, reachable_transition_count=transitions,
            tools={"tlc": TlcEvidence(version=tlc["version"], command=list(observed[-1]["command"]))},
            tlc_exit_status=0)
        result["validation_evidence"] = validated_envelope(evidence).model_dump(mode="json")
        artifacts["validation.json"] = json.dumps(result["validation_evidence"], indent=2) + "\n"
        result.update(status="VALIDATED", claim="BOUNDED_ARCHITECTURE_EVIDENCE",
                      checks_satisfied=True, request_satisfied=True, failed_gate=None)
    except (OSError, ValueError, RuntimeError, RecursionError, MCPPolicyViolation) as exc:
        result.update(code=getattr(exc, "code", "DOMAIN_CHECK_INCOMPLETE"
                          if isinstance(exc, UnsupportedV2Boundary) else "DOMAIN_VALIDATION_FAILED"), message=str(exc),
                      request_satisfied=False, claim="NO_PROOF")
    result["execution_stages"] = [{"stage": item["tool"], **item} for item in observed]
    if model_keys and result["checks_satisfied"]:
        try:
            context.require("workspace_write_new")
            publication = publish_new_artifacts(context.output_root,
                dict(zip(model_keys, (prepared.model.tla, prepared.model.cfg))), context.authority,
                max_total_bytes=limits["max_result_bytes"])
            used += sum(item["size"] for item in publication.values())
            result["model_export"] = {"status": "COMMITTED", "artifacts": publication}
        except (OSError, ValueError, MCPPolicyViolation) as exc:
            result.update(status="MODEL_EXPORT_FAILED", claim="NO_PROOF", request_satisfied=False,
                failed_gate="model_export", message=str(exc), model_export={"status": "FAILED"})
    try:
        result["publication"] = publish_controlled_multistage_evidence(context,
            artifact_prefix="domain-evidence", max_total_bytes=max(0, limits["max_result_bytes"] - used),
            prepared_artifacts=artifacts, workflow="validate-domain", status=result["status"],
            claim=result["claim"], request=request.as_dict(), admission=context.authority.summary(),
            inputs={"sources": result["inputs"], "generated_models": result["generated_models"]},
            stages=result["execution_stages"], semantic_bindings={
                "captured_candidate_base64": captured_text, "preparation": result["preparation"],
                "generated_model_text": model_text, "model_scope": result["model_scope"],
                "static_findings": result.get("static_findings"),
                "traversal": result["traversal"], "tlc": result["tlc"],
                "validation_evidence": result.get("validation_evidence"),
                "checks_satisfied": result["checks_satisfied"], "model_export": result["model_export"],
                "resource_limits": limits, "failed_gate": result["failed_gate"],
                "diagnostic": {key: result[key] for key in ("code", "message") if key in result}},
            claim_limits=result["claim_limits"], request_satisfied=result["request_satisfied"])
        publication = result["publication"]["artifacts"]
        prefix = "domain-evidence/" + result["publication"]["receipt"]["run_id"] + "/"
        for name, identity in result["generated_models"].items():
            identity["path"] = publication[prefix + name]["path"]
        if "validation.json" in artifacts:
            result["validation_artifact"] = publication[prefix + "validation.json"]
        used += sum(item["size"] for item in publication.values())
    except (OSError, ValueError, RuntimeError, MCPPolicyViolation) as exc:
        result.update(status="EVIDENCE_PUBLICATION_FAILED", claim="NO_PROOF", request_satisfied=False,
            failed_gate="evidence_publication", message=str(exc), publication={"status": "FAILED"})
    if export and context.output_root is not None:
        try:
            context.require("workspace_write_new")
            published = publish_new_artifacts(context.output_root, {export: json.dumps(bound(), indent=2) + "\n"},
                context.authority, max_total_bytes=max(0, limits["max_result_bytes"] - used))
            result["result_export"] = {"status": "COMMITTED", "artifacts": published}
        except (OSError, ValueError, MCPPolicyViolation) as exc:
            result.update(status="RESULT_EXPORT_FAILED", claim="NO_PROOF", request_satisfied=False,
                failed_gate="result_export", message=str(exc), result_export={"status": "FAILED"})
    return bound()
