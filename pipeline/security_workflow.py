# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Captured-source Java assessment; formal and SAST evidence are not security proof."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
import tempfile
import time

from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .execution import SourceSnapshot, StrictSandboxExecutor
from .isolated_semgrep import SemgrepScanRequest, run_isolated_semgrep
from .isolated_verification import execute_isolated_verification
from .mcp_artifacts import MCPArtifactError, publish_new_artifacts
from .mcp_policy import MCPPolicyViolation
from .multistage_evidence import publish_multistage_evidence
from .security_assessment import map_formal_vcs
from .workflow_contracts import WORKFLOW_CONTRACT_SCHEMA, VerificationWorkflowRequest, WorkflowContext, bind_workflow_result
from .workflow_services import run_verification


SECURITY_BUDGET = {
    "max_input_bytes": 4 * 1024**2, "max_input_files": 2, "max_path_depth": 32,
    "max_execution_seconds": 180, "max_output_bytes": 2 * 1024**2,
    "max_memory_bytes": 2 * 1024**3, "max_processes": 128,
    "max_file_bytes": 64 * 1024**2, "max_workspace_bytes": 128 * 1024**2,
    "max_temporary_bytes": 64 * 1024**2, "max_result_bytes": 16 * 1024**2,
}


@dataclass(frozen=True)
class SecurityAssessmentWorkflowRequest:
    source: str
    run_sast: bool = True
    result_export: str | None = None

    def __post_init__(self):
        if not isinstance(self.source, str) or not self.source or "\0" in self.source:
            raise ValueError("source must be a nonempty path")
        object.__setattr__(self, "source", str(Path(self.source).expanduser().absolute()))
        if type(self.run_sast) is not bool:
            raise ValueError("run_sast must be boolean")
        if self.result_export is not None and (not isinstance(self.result_export, str)
                or not self.result_export or "\0" in self.result_export):
            raise ValueError("result_export must be a nonempty path or null")

    def required_effects(self):
        return ("workspace_read", "external_execution", "evidence_publication", "workspace_write_new")

    def as_dict(self):
        return {"schema": WORKFLOW_CONTRACT_SCHEMA, "workflow": "assess-security", **asdict(self)}


class _AssessmentExecutor:
    """Spend one aggregate elapsed-time/output allowance across both judges."""
    def __init__(self, context, limits, executor):
        self.context, self.limits, self.executor = context, limits, executor
        self.deadline = time.monotonic() + limits["max_execution_seconds"]
        self.remaining_output = limits["max_output_bytes"]
        self.observations = []

    def execute(self, request):
        self.context.require("external_execution")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.remaining_output <= 0:
            raise ValueError("aggregate execution allowance exhausted")
        caps = {name: min(getattr(request.policy, name), self.limits[name]) for name in (
            "max_memory_bytes", "max_processes", "max_file_bytes", "max_workspace_bytes", "max_temporary_bytes")}
        policy = replace(request.policy, timeout_s=min(request.policy.timeout_s, remaining),
                         max_output_bytes=min(request.policy.max_output_bytes, self.remaining_output), **caps)
        observation = self.executor.execute(replace(request, policy=policy))
        self.observations.append(observation.as_dict())
        self.remaining_output -= len(observation.output.encode("utf-8"))
        return observation


def run_security_assessment(request: SecurityAssessmentWorkflowRequest, context: WorkflowContext,
        *, executor=None) -> dict:
    """Run and publish one assessment; injected executors are trusted test infrastructure."""
    result = {"status": "SECURITY_ASSESSMENT_INCOMPLETE", "claim": "NO_PROOF",
        "request_satisfied": False, "source": request.source, "inputs": [],
        "formal_verification": None, "formal_findings": [],
        "sast": {"status": "NOT_RUN", "scan_complete": False, "findings": []},
        "execution_stages": [], "behavior_equivalence_proved": False,
        "claim_limits": {"security_proved": False, "scope": "single Java source and configured local rules",
            "formal_scope": "OpenJML ESC under the captured contracts and assumptions",
            "sast_scope": "configured local rules only; clean is not security proof",
            "external_io_and_unmodeled_vulnerabilities_assessed": False},
        "publication": {"status": "NOT_ATTEMPTED"}}
    export = request.result_export
    published_size = 0
    runner = None
    limits = {key: min(context.resource_budget.get(key, value), value) for key, value in SECURITY_BUDGET.items()}
    bound = lambda: bind_workflow_result(result, request, context.interface, context=context)
    try:
        if any(type(value) is not int or value <= 0 for value in limits.values()):
            raise ValueError("assessment budgets must be positive integers")
        if context.output_root is None:
            raise ValueError("assessment requires a controlled output root")
        for effect in request.required_effects():
            context.require(effect)
        source, relative = input_path(request.source, context)
        if export:
            destination = context.output_root / export
            if Path(export).is_absolute() or ".." in Path(export).parts or destination.resolve() == source.resolve():
                export = None
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "export aliases an input or escapes the output root")
        if source.suffix.lower() != ".java":
            raise ValueError("assessment currently supports Java .java sources only")
        with input_directory(relative, context) as directory:
            content = capture(relative.name, directory, context, CaptureBudget(limits["max_input_bytes"], 1))
        content.decode("utf-8")
        identity = {"path": relative.as_posix(), "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        result["inputs"] = [identity]
        with tempfile.TemporaryDirectory(prefix="formalspecgen-security-") as temporary:
            root = Path(temporary)
            snapshot = SourceSnapshot.create(root / "input", {source.name: content})
            child = context.child(("workspace_read", "external_execution"))
            child = replace(child, workspace_root=snapshot.root, resource_budget=limits)
            runner = _AssessmentExecutor(child, limits, executor or StrictSandboxExecutor())
            formal = run_verification(VerificationWorkflowRequest(str(snapshot.root / source.name)), child,
                execute=lambda path, **kwargs: execute_isolated_verification(path, executor=runner, **kwargs)).payload
            formal["source"] = relative.as_posix()
            result["formal_verification"] = formal
            result["formal_findings"] = map_formal_vcs(formal.get("output", ""))
            result["execution_stages"].append({"stage": "formal", **formal})
            if not snapshot.validate():
                raise ValueError("captured source changed between stages")
            sast = (run_isolated_semgrep(SemgrepScanRequest(source.name), child, executor=runner)
                    if request.run_sast else {"status": "SKIPPED_BY_REQUEST", "claim": "NO_PROOF",
                        "scan_complete": False, "request_satisfied": True, "findings": [], "execution_observations": []})
            sast["source"] = relative.as_posix()
            for finding in sast["findings"]:
                finding["source"] = relative.as_posix()
            result["sast"] = sast
            result["execution_stages"].append({"stage": "sast", **sast})
            # A successful judge must refer to the captured bytes and enforced execution.
            def valid(observations):
                return bool(observations) and all(
                    item["policy_compliance"] == "ENFORCED" and not item.get("output_truncated")
                    and any(entry["sha256"] == identity["sha256"] and entry["size"] == identity["size"]
                        and Path(entry["path"]).name == source.name for entry in item["snapshot_files"])
                    for item in observations)
            formal_observations = formal.get("execution_stages", [])
            formal_complete = formal.get("status") in {"VERIFIED", "VERIFY_FAILED", "COMPILE_FAILED", "VACUOUS_VERIFIED"} and valid(formal_observations) and all(
                item["status"] in {"COMPLETED", "TOOL_FAILED"} and not item.get("timed_out")
                for item in formal_observations)
            formal_ok = formal.get("request_satisfied", False) and formal_complete
            sast_ok = not request.run_sast or (sast["scan_complete"] and valid(sast["execution_observations"]))
            if not sast_ok or not formal_complete:
                result["status"] = "SECURITY_ASSESSMENT_INCOMPLETE"
            elif not formal_ok:
                result["status"] = "FORMAL_VERIFICATION_FAILED"
            elif result["formal_findings"] or sast["findings"]:
                result["status"] = "SECURITY_FINDINGS"
            else:
                result.update(status="CHECKS_PASSED" if request.run_sast else "FORMALLY_VERIFIED_SAST_SKIPPED",
                              request_satisfied=True)
    except (OSError, ValueError, RuntimeError, MCPPolicyViolation) as exc:
        result.update(request_satisfied=False, code=getattr(exc, "code", "ASSESSMENT_FAILED"), message=str(exc))
    # Retain actual observations even if a later stage raises before returning a result.
    result["execution_observations"] = runner.observations if runner else []
    try:
        context.require("evidence_publication")
        context.require("workspace_write_new")
        if context.output_root is None:
            raise ValueError("missing output root")
        with tempfile.TemporaryDirectory(prefix="formalspecgen-security-evidence-") as temporary:
            receipt = publish_multistage_evidence(Path(temporary), workflow="assess-security",
                status=result["status"], claim="NO_PROOF", request=request.as_dict(), admission=context.authority.summary(),
                inputs={"sources": result["inputs"]}, stages=result["execution_stages"],
                semantic_bindings={"observations": result["execution_observations"],
                    "diagnostic": {key: result[key] for key in ("code", "message") if key in result}},
                claim_limits=result["claim_limits"], request_satisfied=result["request_satisfied"])
            private = Path(receipt["manifest_path"]).parent
            prefix = f"security-evidence/{receipt['run_id']}"
            artifacts = {f"{prefix}/{path.name}": path.read_bytes() for path in private.iterdir() if path.is_file()}
            publication = publish_new_artifacts(context.output_root, artifacts, context.authority,
                                              max_total_bytes=limits["max_result_bytes"])
            published_size = sum(len(value) for value in artifacts.values())
            receipt["manifest_path"] = publication[f"{prefix}/manifest.json"]["path"]
            result["publication"] = {"status": "COMMITTED", "artifacts": publication, "receipt": receipt}
    except (OSError, ValueError, RuntimeError, MCPPolicyViolation) as exc:
        result.update(status="EVIDENCE_PUBLICATION_FAILED", request_satisfied=False,
            code=getattr(exc, "code", "PUBLICATION_FAILED"), message=str(exc), publication={"status": "FAILED"})
    if export and context.output_root is not None:
        try:
            context.require("workspace_write_new")
            artifacts = publish_new_artifacts(context.output_root, {export: json.dumps(bound(), indent=2) + "\n"},
                context.authority, max_total_bytes=max(0, limits["max_result_bytes"] - published_size))
            result["result_export"] = {"status": "COMMITTED", "artifacts": artifacts}
        except (OSError, ValueError, MCPPolicyViolation) as exc:
            result.update(status="RESULT_EXPORT_FAILED", request_satisfied=False,
                code=getattr(exc, "code", "PUBLICATION_FAILED"), message=str(exc), result_export={"status": "FAILED"})
    return bound()
