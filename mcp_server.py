"""Optional MCP façade for FormalSpecGen's structured verification workflows.

Install the optional SDK with ``pip install 'formalspecgen[mcp]'``.  The core functions in this
module remain importable without the SDK, which keeps the CLI and test environments lightweight.

Workspace tools confine inputs and outputs to the current workspace and return
structured verdict objects; a tool failure is never converted into a success
claim. The admitted catalogue also includes an operator-configured A2A bridge
whose workers can return unaccepted candidate artifacts. Deliberately NOT
exposed: ``promote-domain`` (hash-bound human
acceptance of reviewed artifacts is a trust action that stays with the CLI),
the interactive clarification wizards (``domain``, non-canonical ``draft``,
``design-system``), and the reviewer trust actions ``sign-artifact`` /
``manage-trust`` (signing and key policy require the human reviewer's own
GPG key — an agent must never sign or authorize on a reviewer's behalf).
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from functools import wraps
from pathlib import Path
from typing import Any, Callable

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - exercised by environments without the optional SDK
    FastMCP = None

from pipeline import config
from pipeline.lifecycle import EvidenceClaim, PipelineState, RunLedger, sha256_text
from pipeline.mcp_artifacts import (
    MCPArtifactError,
    publish_new_artifacts,
)
from pipeline.mcp_policy import (
    MCPAdmission,
    MCPPolicyViolation,
    authorize_mcp_invocation,
    require_mcp_effect,
)
from pipeline.mcp_provider_policy import resolve_documentation_model
from pipeline.isolated_verification import (
    IsolatedVerificationResult,
    execute_isolated_verification,
)
from pipeline.verify import verify_detailed
from pipeline.workflow_services import (
    run_documentation_preparation,
    run_java_inspection,
    run_verification,
)
from pipeline.workflow_contracts import (
    DocumentationWorkflowRequest,
    InspectionWorkflowRequest,
    VerificationWorkflowRequest,
    WorkflowContext,
    WorkflowInterface,
    bind_workflow_result,
)


MCP_DOCUMENT_MAX_INPUT_BYTES = 1 * 1024 * 1024
MCP_DOCUMENT_MAX_RESULT_BYTES = 2 * 1024 * 1024
MCP_INSPECT_MAX_INPUT_BYTES = 1 * 1024 * 1024
MCP_INSPECT_MAX_RESULT_BYTES = 2 * 1024 * 1024


def _operator_controlled_path(
        variable: str, *, require_file: bool = False) -> Path:
    raw = os.environ.get(variable)
    if not raw:
        raise ValueError(f"{variable} is not configured")
    supplied = Path(raw).expanduser()
    if not supplied.is_absolute():
        raise ValueError(f"{variable} must be an absolute operator-controlled path")
    if supplied.is_symlink():
        raise ValueError(f"{variable} must not be a symlink")
    path = supplied.resolve()
    workspace = Path.cwd().resolve()
    if path == workspace or workspace in path.parents:
        raise ValueError(f"{variable} must be outside the agent workspace")
    if require_file:
        if not path.is_file():
            raise ValueError(f"{variable} must identify a regular file")
        if path.stat().st_mode & 0o022:
            raise ValueError(f"{variable} must not be group- or world-writable")
    elif path.exists() and (not path.is_dir() or path.stat().st_mode & 0o022):
        raise ValueError(
            f"{variable} must be a protected directory when it already exists")
    return path


def _configured_a2a_coordinator(*, create_state: bool):
    """Build the coordinator exclusively from server-side configuration."""
    from pipeline.a2a_coordination import (
        A2ACoordinator,
        CoordinationPolicy,
        OfficialA2AWorkerClient,
        TaskStore,
    )

    policy_path = _operator_controlled_path(
        "FORMALSPECGEN_A2A_POLICY", require_file=True)
    state_root = _operator_controlled_path("FORMALSPECGEN_A2A_STATE_ROOT")
    return A2ACoordinator(
        CoordinationPolicy.load(policy_path),
        TaskStore(state_root, create=create_state),
        OfficialA2AWorkerClient(),
        project_root=Path.cwd(),
    )


def _a2a_principal() -> str:
    principal = os.environ.get("FORMALSPECGEN_A2A_PRINCIPAL", "").strip()
    if not principal:
        raise ValueError("FORMALSPECGEN_A2A_PRINCIPAL is not configured")
    return principal


def _coordination_response(record: dict[str, Any], admission: MCPAdmission) -> dict[str, Any]:
    state = str(record.get("state", "unknown"))
    unresolved = {"dispatching", "dispatch_uncertain", "cancellation_pending"}
    inconsistent = record.get("coordination_status") == "inconsistent"
    return {
        "status": "COORDINATION_INCONSISTENT" if inconsistent else state.upper(),
        "claim": "NO_PROOF",
        "request_satisfied": (
            not inconsistent
            and state not in {"failed", "rejected"} | unresolved),
        "work_item_id": record.get("work_item_id"),
        "worker_task": record,
        "worker_completed": state == "completed",
        "coordination_inconsistent": inconsistent,
        "implementation_accepted": False,
        "mcp_admission": admission.summary(),
    }


def _coordination_error(exc: Exception) -> dict[str, Any]:
    from pipeline.a2a_coordination import A2ACoordinationError

    if isinstance(exc, A2ACoordinationError):
        return exc.as_dict()
    return {
        "status": "FAIL", "claim": "NO_PROOF", "request_satisfied": False,
        "code": "invalid_request", "message": str(exc),
    }


def _strict_mcp_isolation_enabled() -> bool:
    """Return whether MCP is restricted to its explicitly isolated catalogue."""
    return os.environ.get("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", "1") != "0"


def _isolation_unsupported(tool: str) -> dict[str, Any]:
    return {
        "status": "ISOLATION_UNSUPPORTED",
        "claim": "NO_PROOF",
        "request_satisfied": False,
        "tool": tool,
        "strict_isolation_supported": False,
        "durable_publication_supported": False,
        "message": (
            "MCP strict mode permits only capabilities with an explicitly "
            "enforced isolation profile"
        ),
    }


def _workspace_path(value: str, *, must_exist: bool = True) -> Path:
    root = Path.cwd().resolve()
    path = Path(value).expanduser()
    path = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if root != path and root not in path.parents:
        raise ValueError("path must remain inside the current workspace")
    if must_exist and not path.exists():
        raise FileNotFoundError(str(path))
    return path


def _designated_mcp_output_root() -> Path:
    """Resolve the server-controlled output root without following its symlinks."""
    value = os.environ.get(
        "FORMALSPECGEN_MCP_OUTPUT_ROOT", ".formalspecgen/mcp-output")
    workspace = Path.cwd().resolve()
    supplied = Path(value).expanduser()
    lexical = (supplied.absolute() if supplied.is_absolute()
               else (Path.cwd() / supplied).absolute())
    resolved = lexical.resolve()
    if resolved != workspace and workspace not in resolved.parents:
        raise MCPArtifactError(
            "OUTPUT_SCOPE_VIOLATION",
            "MCP output root must remain inside the current workspace")
    current = workspace
    try:
        parts = lexical.relative_to(workspace).parts
    except ValueError as exc:
        raise MCPArtifactError(
            "OUTPUT_SCOPE_VIOLATION",
            "MCP output root must remain inside the current workspace") from exc
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise MCPArtifactError(
                "OUTPUT_SYMLINK_REJECTED",
                "MCP output root must not contain symlinks")
    return lexical


def _guarded(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run a tool body, converting path violations into fail-closed verdicts."""
    try:
        return call()
    except (ValueError, FileNotFoundError) as exc:
        message = str(exc)
        code = ("path_outside_workspace" if "workspace" in message
                else "input_unavailable" if isinstance(exc, FileNotFoundError)
                else "invalid_request")
        return {"status": "FAIL", "claim": "NO_PROOF", "code": code, "message": message}


def _load_system_plan(plan_path: str, mode: str) -> dict[str, Any]:
    """Decode a plan and validate every referenced input within the workspace."""
    path = _workspace_path(plan_path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("system plan must be a JSON object")
    components = value.get("components")
    if not isinstance(components, list):
        raise ValueError("system plan components must be a list")
    required = ({"interface_file", "reviewed_domain", "validation_evidence"}
                if mode == "implement" else {"file"})
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ValueError(f"system component {index} must be an object")
        for field in required:
            raw = component.get(field)
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError(f"system component {index} requires {field}")
            component[field] = str(_workspace_path(raw))
    composition = value.get("composition")
    if isinstance(composition, dict) and isinstance(composition.get("files"), dict):
        composition["files"] = {
            name: str(_workspace_path(raw))
            for name, raw in composition["files"].items()
        }
    return value


def _publish_verification_evidence(
        path: Path, mode: str, detailed, decision: dict,
        admission: MCPAdmission, context: WorkflowContext,
        request: VerificationWorkflowRequest) -> dict:
    context.require("evidence_publication")
    run_root = Path.cwd() / ".formalspecgen" / "mcp-evidence" / uuid.uuid4().hex
    ledger = RunLedger(run_root)
    try:
        claim = EvidenceClaim(decision.get("claim", "NO_PROOF"))
    except ValueError:
        claim = EvidenceClaim.NO_PROOF
    observations = [item.as_dict() for item in getattr(detailed, "observations", ())]
    observation = detailed.observation.as_dict() if detailed.observation else None
    tool_identities = list(decision.get("tool_identities", []))
    if not tool_identities and observation and observation.get("command"):
        executable = Path(observation["command"][0])
        if executable.is_file():
            content = executable.read_bytes()
            tool_identities.append({
                "path": str(executable), "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            })
    snapshot_files = [record for stage in observations
                      for record in stage.get("snapshot_files", [])]
    executed_source = next(
        (item for item in snapshot_files
         if item.get("path") in {path.name, f"reviewed/{path.name}"}), None)
    source_sha256 = (executed_source.get("sha256") if executed_source
                     else sha256_text(path.read_text(encoding="utf-8")))
    ledger.record(
        PipelineState.PROOF, decision.get("status", "UNKNOWN"), claim=claim,
        details={"mode": mode, "request_satisfied": decision.get("request_satisfied", False),
                 "mcp_admission": admission.summary(),
                 "workflow_request": request.as_dict()},
        evidence={
            "source_path": str(path),
            "source_sha256": source_sha256,
            "source_snapshot_manifest_sha256": (
                observation.get("snapshot_manifest_sha256") if observation else None),
            "raw_output_sha256": sha256_text(detailed.output),
            "backend_exit_code": detailed.exit_code,
            "tool_identities": tool_identities,
            "execution_observation": observation,
            "execution_stages": observations,
        })
    manifest = ledger.commit({
        "final_status": decision.get("status", "UNKNOWN"),
        "claim": decision.get("claim", "NO_PROOF"),
        "request_satisfied": decision.get("request_satisfied", False),
        "source_sha256": source_sha256,
        "source_snapshot_manifest_sha256": (
            observation.get("snapshot_manifest_sha256") if observation else None),
        "effective_arguments": observation.get("command") if observation else None,
        "execution_policy_compliance": (
            observation.get("policy_compliance") if observation else
            "NOT_APPLICABLE" if not admission.permits("external_execution")
            else "NOT_ENFORCED"),
        "execution_observation": observation,
        "execution_stages": observations,
        "tool_identities": tool_identities,
        "mcp_admission": admission.summary(),
        "workflow_request": request.as_dict(),
        "claim_policy_version": "verification-policy-v1",
    })
    return {
        "run_id": ledger.run_id,
        "manifest_path": str(manifest),
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "publication_status": "COMMITTED",
    }


def verify_code(
        source: str, mode: str = "esc", backend: str = "prusti",
        result_export: str | None = None) -> dict[str, Any]:
    """Verify Java/JML, Rust, C/ACSL, or C++ under an admitted strict profile."""
    request = VerificationWorkflowRequest(
        source, mode=mode, backend=backend, result_export=result_export)
    effects = request.required_effects(WorkflowInterface.MCP)
    admission = authorize_mcp_invocation(
        "verify_code", mode=request.mode, language=request.language,
        backend=request.effective_backend, effects=effects)
    if _strict_mcp_isolation_enabled() and not admission.admitted:
        return bind_workflow_result(
            admission.rejection(), request, WorkflowInterface.MCP)
    context = (WorkflowContext.for_mcp(
        admission, effects,
        output_root=(_designated_mcp_output_root()
                     if request.result_export is not None else None))
               if admission.admitted else None)
    try:
        path = (context.resolve_input(request.source) if context
                else _workspace_path(request.source))
    except (ValueError, FileNotFoundError) as exc:
        message = str(exc)
        result = {
            "status": "FAIL", "claim": "NO_PROOF", "request_satisfied": False,
            "code": ("path_outside_workspace" if "workspace" in message
                     else "input_unavailable"), "message": message,
            "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    assert context is not None
    def execute(source: Path, *, mode: str, backend: str):
        if request.language in {"java", "jml"}:
            detailed = verify_detailed(source, mode=mode)
            return IsolatedVerificationResult(
                {"exit_code": detailed.exit_code, "output": detailed.output},
                (detailed.observation,) if detailed.observation else ())
        return execute_isolated_verification(source, mode=mode, backend=backend)

    service = run_verification(request, context, execute=execute)
    detailed = service.backend_result
    decision = dict(service.payload)
    try:
        receipt = _publish_verification_evidence(
            path, request.mode, detailed, decision, admission, context, request)
    except (OSError, RuntimeError, ValueError, MCPPolicyViolation) as exc:
        result = {
            **decision, "status": "EVIDENCE_PUBLICATION_FAILED",
            "claim": "NO_PROOF", "request_satisfied": False,
            "message": str(exc), "file": str(path),
            "strict_isolation_supported": True,
            "durable_publication_supported": False,
            "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    result = {
        **decision, "file": str(path), "evidence": receipt,
        "strict_isolation_supported": True,
        "durable_publication_supported": True,
        "mcp_admission": admission.summary(),
    }
    try:
        if request.result_export is not None:
            export = Path(request.result_export)
            if export.is_absolute() or ".." in export.parts or export.suffix.lower() != ".json":
                raise MCPArtifactError(
                    "OUTPUT_SCOPE_VIOLATION",
                    "verification export must be a relative JSON path")
            context.require("workspace_write_new")
            assert context.output_root is not None
            bound = bind_workflow_result(
                result, request, WorkflowInterface.MCP, context=context)
            artifacts = publish_new_artifacts(
                context.output_root,
                {request.result_export: json.dumps(
                    bound, indent=2, ensure_ascii=False, default=str) + "\n"},
                admission, max_total_bytes=2 * 1024 * 1024)
            result["result_export"] = {
                "status": "COMMITTED", "kind": "verification-result-export",
                "artifacts": artifacts,
            }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except (OSError, ValueError, MCPPolicyViolation, MCPArtifactError) as exc:
        result = {
            **result, "status": "RESULT_EXPORT_FAILED",
            "claim": "NO_PROOF", "request_satisfied": False,
            "message": str(exc),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)


def validate_architecture(artifact_path: str, timeout: int = 120) -> dict[str, Any]:
    """Validate a unified architecture through its typed model and TLC gate."""
    from pipeline.architecture_tla_renderer import render_unified_architecture
    from pipeline.staged_architecture import UnifiedArchitecture
    from pipeline.architecture_tlc_gate import validate_architecture_with_tlc
    path = _workspace_path(artifact_path)
    try:
        architecture = UnifiedArchitecture.model_validate(json.loads(path.read_text(encoding="utf-8")))
        tla, cfg = render_unified_architecture(architecture)
        with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-") as directory:
            root = Path(directory)
            tla_path, cfg_path = root / "architecture.tla", root / "architecture.cfg"
            tla_path.write_text(tla, encoding="utf-8"); cfg_path.write_text(cfg, encoding="utf-8")
            result = validate_architecture_with_tlc(tla_path, cfg_path, config.TLC_JAR,
                                                    config.JAVA_BIN, timeout)
        return {"artifact": str(path), **result}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status": "ARCHITECTURE_INVALID", "claim": "NO_PROOF", "message": str(exc)}


def implement_code(spec_path: str, provider: str = "ollama",
                   assurance_level: str = "critical",
                   v2_reviewed_domain: str | None = None,
                   v2_validation_evidence: str | None = None) -> dict[str, Any]:
    """Run the native implementation loop for a workspace source/spec scaffold.

    Passing the reviewed-domain and validation-evidence pair enters the V2
    refinement gate: a native proof then binds to the promoted candidate
    hash and can mint SOURCE_MODEL_REFINEMENT.
    """
    from pipeline.orchestrator import run_implementation_loop
    def run() -> dict[str, Any]:
        domain = (_workspace_path(v2_reviewed_domain)
                  if v2_reviewed_domain is not None else None)
        evidence = (_workspace_path(v2_validation_evidence)
                    if v2_validation_evidence is not None else None)
        return run_implementation_loop(
            _workspace_path(spec_path), provider=provider,
            assurance_level=assurance_level,
            v2_reviewed_domain=domain, v2_validation_evidence=evidence)
    return _guarded(run)


def inspect_code(
        source: str, result_export: str | None = None) -> dict[str, Any]:
    """Run deterministic Java/JML inspection with an optional controlled export."""
    request = InspectionWorkflowRequest(source, result_export=result_export)
    effects = request.required_effects(WorkflowInterface.MCP)
    admission = authorize_mcp_invocation(
        "inspect_code", mode=request.mode, language=request.language,
        backend=request.effective_backend, effects=effects)
    if not admission.admitted:
        return bind_workflow_result(
            admission.rejection(), request, WorkflowInterface.MCP)
    context = None
    try:
        context = WorkflowContext.for_mcp(
            admission, effects,
            output_root=(_designated_mcp_output_root()
                         if request.result_export is not None else None),
            resource_budget={
                "max_input_bytes": MCP_INSPECT_MAX_INPUT_BYTES,
                "max_result_bytes": MCP_INSPECT_MAX_RESULT_BYTES,
            })
        result = run_java_inspection(request, context)
        result = {**result, "mcp_admission": admission.summary()}
        bound = bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
        if request.result_export is None or result.get("status") != "INSPECTED":
            return bound
        export = Path(request.result_export)
        if export.is_absolute() or ".." in export.parts or export.suffix.lower() != ".json":
            raise MCPArtifactError(
                "OUTPUT_SCOPE_VIOLATION",
                "inspection export must be a relative JSON path")
        context.require("workspace_write_new")
        assert context.output_root is not None
        artifacts = publish_new_artifacts(
            context.output_root,
            {request.result_export: json.dumps(
                bound, indent=2, ensure_ascii=False, default=str) + "\n"},
            admission, max_total_bytes=MCP_INSPECT_MAX_RESULT_BYTES)
        result["publication"] = {
            "status": "COMMITTED", "kind": "unreviewed-inspection-export",
            "artifacts": artifacts,
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except MCPArtifactError as exc:
        result = {
            "status": "FAIL", "claim": "NO_PROOF", "code": exc.code,
            "message": str(exc), "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except (MCPPolicyViolation, ValueError, FileNotFoundError) as exc:
        message = str(exc)
        code = ("path_outside_workspace" if "workspace" in message
                else "input_unavailable" if isinstance(exc, FileNotFoundError)
                else "MCP_EFFECT_NOT_AUTHORIZED"
                if isinstance(exc, MCPPolicyViolation) else "invalid_request")
        result = {
            "status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except OSError as exc:
        result = {
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "ARTIFACT_PUBLICATION_FAILED", "message": str(exc),
            "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)


def analyze_codebase(target_dir: str, out_dir: str = "extracted",
                     project_root: str = ".") -> dict[str, Any]:
    """Extract unreviewed architecture and V2 domain candidates from a source tree."""
    from pipeline.codebase_analysis import analyze_codebase as run_analysis
    return _guarded(lambda: run_analysis(
        _workspace_path(target_dir), _workspace_path(out_dir, must_exist=False),
        _workspace_path(project_root, must_exist=False)))


def document_code(
        source: str, out: str, project_root: str = ".",
        no_llm: bool = False, provider: str = "ollama",
        model: str | None = None,
        result_export: str | None = None) -> dict[str, Any]:
    """Create bounded, unreviewed Java documentation artifacts."""
    request = DocumentationWorkflowRequest(
        source, out, project_root=project_root, no_llm=no_llm,
        provider=provider, model=model, result_export=result_export)
    effects = request.required_effects(WorkflowInterface.MCP)
    admission = authorize_mcp_invocation(
        "document_code", mode=request.mode, language=request.language,
        backend=request.effective_backend, provider=request.provider,
        effects=effects)
    if not admission.admitted:
        return bind_workflow_result(
            admission.rejection(), request, WorkflowInterface.MCP)
    context = None
    try:
        context = WorkflowContext.for_mcp(
            admission, effects, output_root=_designated_mcp_output_root(),
            resource_budget={
                "max_input_bytes": MCP_DOCUMENT_MAX_INPUT_BYTES,
                "max_result_bytes": MCP_DOCUMENT_MAX_RESULT_BYTES,
                "max_provider_response_bytes": 128 * 1024,
            })
        output_path = Path(request.out)
        if (output_path.is_absolute() or ".." in output_path.parts
                or output_path.suffix.lower() != ".md"):
            raise MCPArtifactError(
                "OUTPUT_SCOPE_VIOLATION",
                "documentation output must be a relative Markdown path")
        project_path = Path(request.project_root)
        if project_path.is_absolute() or ".." in project_path.parts:
            raise MCPArtifactError(
                "OUTPUT_SCOPE_VIOLATION",
                "documentation project root must be a relative output namespace")
        if request.result_export is not None:
            export_path = Path(request.result_export)
            if (export_path.is_absolute() or ".." in export_path.parts
                    or export_path.suffix.lower() != ".json"):
                raise MCPArtifactError(
                    "OUTPUT_SCOPE_VIOLATION",
                    "documentation export must be a relative JSON path")
        output_root = context.output_root
        assert output_root is not None
        prepared = run_documentation_preparation(
            request, context, resolve_model=resolve_documentation_model)
        if prepared.bundle is None:
            result = {**prepared.payload, "mcp_admission": admission.summary()}
            return bind_workflow_result(
                result, request, WorkflowInterface.MCP, context=context)
        candidate_name = (project_path / "domains" / "candidates" /
                          prepared.bundle.candidate_filename).as_posix()
        document_path = str(output_root / request.out)
        candidate_path = str(output_root / candidate_name)
        result = dict(prepared.payload)
        result.update({
            "document": document_path,
            "candidate": candidate_path,
            "mcp_admission": admission.summary(),
        })
        bound = bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
        pending: dict[str, str] = {
            request.out: prepared.bundle.document_text,
            candidate_name: prepared.bundle.candidate_text,
        }
        if request.result_export is not None:
            pending[request.result_export] = json.dumps(
                bound, indent=2, ensure_ascii=False, default=str) + "\n"
        artifacts = publish_new_artifacts(
            output_root, pending, admission,
            max_total_bytes=MCP_DOCUMENT_MAX_RESULT_BYTES)
        result["artifacts"] = artifacts
        result["publication"] = {
            "status": "COMMITTED",
            "kind": "unreviewed-documentation-artifacts",
            "artifacts": artifacts,
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except MCPArtifactError as exc:
        result = {
            "status": "FAIL", "claim": "NO_PROOF", "code": exc.code,
            "message": str(exc), "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except MCPPolicyViolation as exc:
        result = {
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "MCP_EFFECT_NOT_AUTHORIZED", "message": str(exc),
            "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except (ValueError, FileNotFoundError) as exc:
        message = str(exc)
        code = ("path_outside_workspace" if "workspace" in message
                else "input_unavailable" if isinstance(exc, FileNotFoundError)
                else "invalid_request")
        result = {
            "status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)
    except OSError as exc:
        result = {
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "ARTIFACT_PUBLICATION_FAILED", "message": str(exc),
            "mcp_admission": admission.summary(),
        }
        return bind_workflow_result(
            result, request, WorkflowInterface.MCP, context=context)


def assess_security(source: str, run_sast: bool = True) -> dict[str, Any]:
    """Assess a Java source against formal verification and Semgrep SAST evidence."""
    from pipeline.security_assessment import assess_security as run_assessment
    return _guarded(lambda: run_assessment(_workspace_path(source), run_sast=run_sast))


def security_inspect(source: str) -> dict[str, Any]:
    """Inspect sources (file or directory) for findings mapped to CWEs."""
    from pipeline.security_poc import inspect_security as run_inspection
    return _guarded(lambda: run_inspection(_workspace_path(source)))


def security_exploit(report_path: str, target: str,
                     out_dir: str = "security-pocs") -> dict[str, Any]:
    """Generate review-only PoC source templates from an inspection report."""
    from pipeline.security_poc import generate_pocs as run_pocs
    return _guarded(lambda: run_pocs(
        _workspace_path(report_path), _workspace_path(target),
        _workspace_path(out_dir, must_exist=False)))


def remediate_code(target: str, report: str, out_dir: str = "remediated",
                   provider: str = "ollama", model: str | None = None) -> dict[str, Any]:
    """Generate a patched copy from a vulnerability report and prove it with ESC."""
    from pipeline.remediation import remediate as run_remediation
    return _guarded(lambda: run_remediation(
        _workspace_path(target), _workspace_path(report),
        _workspace_path(out_dir, must_exist=False), provider=provider, model=model))


def correct_behavior(target: str, cwe: str, out_dir: str = "corrections",
                     provider: str = "ollama", model: str | None = None,
                     max_attempts: int = 3, strategy: str | None = None,
                     hardware: str | None = None,
                     struct_size_bytes: int | None = None,
                     pool_field: str | None = None,
                     auto_strategy: bool = False) -> dict[str, Any]:
    """Strengthen a contract per CWE and prove the corrected behavior with ESC.

    ``strategy`` selects one of the nine deterministic corrections (four
    capacity-bounding strategies for CWE-400 plus the five hardening
    strategies); ``hardware`` + ``struct_size_bytes`` derive the capacity
    from silicon; ``auto_strategy`` routes the strategy from the code's
    own shape (CWE-scoped, explicit opt-in).
    """
    from pipeline.behavior_correction import correct_behavior as run_correction
    profile = _workspace_path(hardware) if hardware is not None else None
    return _guarded(lambda: run_correction(
        _workspace_path(target), cwe, _workspace_path(out_dir, must_exist=False),
        provider=provider, model=model, max_attempts=max_attempts,
        strategy=strategy, hardware=profile,
        struct_size_bytes=struct_size_bytes, pool_field=pool_field,
        auto_strategy=auto_strategy))


def architecture(stub_path: str, abstraction: str = "atomic_operations",
                 clarifications: str = "") -> dict[str, Any]:
    """Check a bounded JML architecture abstraction with the real TLC gate."""
    from pipeline.tla_backend import generate_and_check
    code = _workspace_path(stub_path).read_text(encoding="utf-8")
    return _guarded(lambda: generate_and_check(
        code, clarifications=clarifications, abstraction=abstraction))


def system(plan_path: str, mode: str = "implement", out_dir: str = "runs/system",
           max_workers: int = 4) -> dict[str, Any]:
    """Run the parallel system orchestrator over an architecture artifact.

    Modes mirror the CLI: ``implement`` (isolated component proofs plus the
    composition gate), ``refactor`` (bounded extract-method modernization),
    and ``correct`` (isolated one-CWE-per-subagent hardening sub-agents).
    """
    from pipeline import system_orchestrator
    def dispatch() -> dict[str, Any]:
        if mode not in {"implement", "refactor", "correct"}:
            raise ValueError(f"unknown system mode {mode!r}: expected implement, "
                             "refactor, or correct")
        plan = _load_system_plan(plan_path, mode)
        destination = _workspace_path(out_dir, must_exist=False)
        if mode == "implement":
            return system_orchestrator.verify_system(plan, out_dir=destination,
                                                     max_workers=max_workers)
        if mode == "refactor":
            return system_orchestrator.refactor_system(plan, out_dir=destination,
                                                       max_workers=max_workers)
        if mode == "correct":
            return system_orchestrator.correct_system(plan, out_dir=destination,
                                                      max_workers=max_workers)
        raise AssertionError("unreachable")
    return _guarded(dispatch)


def apply_refactor(source: str, inspection: str, pattern: str, method: str,
                   out: str) -> dict[str, Any]:
    """Apply one hash-bound refactor profile and immediately run its proof gate."""
    from pipeline.refactor_actions import apply_refactor as run_apply
    return _guarded(lambda: run_apply(
        _workspace_path(source), _workspace_path(inspection), pattern, method,
        _workspace_path(out, must_exist=False)))


def verify_refactor(baseline: str, refactored: str) -> dict[str, Any]:
    """Prove a contract-preserving refactor (file -> single-file gate, dir -> multifile)."""
    def run() -> dict[str, Any]:
        from pipeline.refactor_gate import (
            verify_contract_preserving_refactor, verify_multifile_contract_refactor)
        base = _workspace_path(baseline)
        target = _workspace_path(refactored)
        if target.is_dir():
            return verify_multifile_contract_refactor(base, target)
        return verify_contract_preserving_refactor(base, target)
    return _guarded(run)


def verify_bisimulation(baseline: str, refactored: str, mapping: str) -> dict[str, Any]:
    """Validate a bisimulation preflight mapping without claiming equivalence."""
    from pipeline.bisimulation import verify_bisimulation_inputs as run_bisimulation
    return _guarded(lambda: run_bisimulation(
        _workspace_path(baseline), _workspace_path(refactored), _workspace_path(mapping)))


def optimize_algorithm(source: str, out: str, strategy: str,
                       provider: str = "ollama", model: str | None = None) -> dict[str, Any]:
    """Request a constrained algorithm rewrite and re-run ESC plus the refactor gate."""
    from pipeline.algorithm_optimization import optimize_algorithm as run_optimize
    return _guarded(lambda: run_optimize(
        _workspace_path(source), _workspace_path(out, must_exist=False),
        strategy=strategy, provider=provider, model=model))


def discover_algorithms(source: str, out_dir: str = "discovered",
                        strategies: list[str] | None = None, provider: str = "ollama",
                        model: str | None = None, max_workers: int = 3) -> dict[str, Any]:
    """Fan a specification out across strategy prompts, keeping ESC-verified candidates."""
    from pipeline.algorithm_discovery import discover_algorithms as run_discovery
    return _guarded(lambda: run_discovery(
        _workspace_path(source), _workspace_path(out_dir, must_exist=False),
        strategies=strategies, provider=provider, model=model, max_workers=max_workers))


def validate_domain(name: str, project_root: str = ".",
                    timeout: int | None = None) -> dict[str, Any]:
    """Validate a V2 domain candidate with the bounded traverser and real TLC."""
    def run() -> dict[str, Any]:
        from pipeline.domain_v2_validation import validate_domain as run_validation
        try:
            root = _workspace_path(project_root, must_exist=False)
        except (ValueError, FileNotFoundError):
            raise  # path violations stay path failures, not validation failures
        try:
            evidence = run_validation(name, project_root=str(root), timeout=timeout)
        except Exception as exc:  # validation failures are evidence, not crashes
            return {"status": "VALIDATION_FAILED", "claim": "NO_PROOF",
                    "message": str(exc)[:400]}
        return {"status": "VALIDATED", "claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
                **evidence.model_dump(mode="json")}
    return _guarded(run)


def compose(artifact_path: str, v2_dir: str | None = None, run_esc: bool = True,
            actors: list[str] | None = None) -> dict[str, Any]:
    """Compose reviewed V2 domains and prove the glue with OpenJML ESC."""
    def run() -> dict[str, Any]:
        from pipeline.composition_render import verify_composition
        value = json.loads(_workspace_path(artifact_path).read_text(encoding="utf-8"))
        resolved = _workspace_path(v2_dir) if v2_dir else None
        return verify_composition(json.dumps(value), resolved, run_esc=run_esc, actors=actors)
    return _guarded(run)


def reverify_composition(artifact_path: str, changed_module: str,
                         v2_dir: str | None = None, run_esc: bool = True) -> dict[str, Any]:
    """Re-prove composition after a reviewed module contract changed."""
    def run() -> dict[str, Any]:
        from pipeline.composition_render import reverify_composition as run_reverify
        value = json.loads(_workspace_path(artifact_path).read_text(encoding="utf-8"))
        resolved = _workspace_path(v2_dir) if v2_dir else None
        return run_reverify(json.dumps(value), changed_module, resolved, run_esc=run_esc)
    return _guarded(run)


def unified_system(artifact_path: str, evidence_path: str, out_dir: str,
                   language: str = "java") -> dict[str, Any]:
    """Lower a validated unified architecture into sources and prove the core."""
    from pipeline.unified_system_runner import run_unified_system as run_lowering
    return _guarded(lambda: run_lowering(
        _workspace_path(artifact_path), _workspace_path(evidence_path),
        _workspace_path(out_dir, must_exist=False), language=language))


def draft_canonical_contract(domain: str, lang: str = "java", out_file: str | None = None,
                             project_root: str = ".", requirement: str = "") -> dict[str, Any]:
    """Deterministically lower a reviewed V2 domain into Java/JML, Rust, C, or C++."""
    def run() -> dict[str, Any]:
        from pipeline.canonical_draft import canonical_draft
        resolved_out = str(_workspace_path(out_file, must_exist=False)) if out_file else None
        return canonical_draft(domain, lang=lang, out_file=resolved_out,
                               project_root=str(_workspace_path(
                                   project_root, must_exist=False)),
                               requirement=requirement)
    return _guarded(run)


def prove_equivalence(baseline: str, refactored: str,
                      mapping: str) -> dict[str, Any]:
    """Prove bounded behavioral bisimulation between two V2 machines."""
    from pipeline.equivalence import prove_equivalence as run_proof
    return _guarded(lambda: run_proof(
        _workspace_path(baseline), _workspace_path(refactored),
        _workspace_path(mapping)))


def generate_traceability_matrix(domain: str, source: str,
                                 requirements: str,
                                 out: str = "traceability-matrix.md") -> dict[str, Any]:
    """Map REQ-### requirements to V2 invariants and source lines."""
    from pipeline.traceability import (
        generate_traceability_matrix as run_matrix, write_matrix,
    )
    def run() -> dict[str, Any]:
        matrix = run_matrix(_workspace_path(domain),
                            _workspace_path(source),
                            _workspace_path(requirements))
        path = write_matrix(matrix, _workspace_path(out, must_exist=False))
        return {"status": "TRACEABILITY_GENERATED",
                "matrix_file": str(path), **matrix}
    return _guarded(run)


def verify_unbounded(source: str, invariant: str | None = None,
                     provider: str = "ollama") -> dict[str, Any]:
    """Prove a loop invariant inductive (k-induction, no unrolling)."""
    from pipeline.unbounded import verify_unbounded as run_unbounded
    return _guarded(lambda: run_unbounded(
        _workspace_path(source), invariant=invariant, provider=provider))


def verify_linearizability(source: str, domain: str) -> dict[str, Any]:
    """Java lock correspondence plus bounded-history linearizability."""
    from pipeline.linearizability import (
        verify_linearizability as run_linearizability,
    )
    return _guarded(lambda: run_linearizability(
        _workspace_path(source), _workspace_path(domain)))


def verify_distributed(domain: str, message_fields: str,
                       faults: str = "message_loss,duplication,reordering"
                       ) -> dict[str, Any]:
    """Safety under injected network faults (comma-separated fields/faults)."""
    from pipeline.distributed import verify_distributed as run_distributed
    def run() -> dict[str, Any]:
        fields = [item.strip() for item in message_fields.split(",") if item.strip()]
        fault_list = [item.strip() for item in faults.split(",") if item.strip()]
        return run_distributed(_workspace_path(domain),
                               faults=fault_list, message_fields=fields)
    return _guarded(run)


def verify_heap(source: str, provider: str = "ollama") -> dict[str, Any]:
    """Unbounded heap-shape verification via ghost predicates (Rust/Prusti;
    C .c/.h intrusive lists on Frama-C WP)."""
    from pipeline.heap import verify_heap as run_heap
    return _guarded(lambda: run_heap(_workspace_path(source),
                                     provider=provider))


def verify_lockfree(source: str) -> dict[str, Any]:
    """OS lane 1: lock-free SPSC-ring linearizability — real ESBMC thread
    interleaving (capacity invariant under every interleaving) plus the
    structural linearization-point coverage gate; scheduler fairness is
    the human-accepted assumption."""
    from pipeline.lockfree import verify_lockfree as run_lockfree
    return _guarded(lambda: run_lockfree(_workspace_path(source)))


def verify_hal(source: str) -> dict[str, Any]:
    """HAL/MMIO register discipline: bitfield register separation and
    PADDR<->PPTR window round-trip, machine-proved by Frama-C WP; device
    semantics are recorded as human-accepted assumptions."""
    from pipeline.hal_mmio import verify_hal as run_hal
    return _guarded(lambda: run_hal(_workspace_path(source)))


def macro_translate(source: str, dictionary: str,
                    provider: str = "ollama") -> dict[str, Any]:
    """M35 semantic macro expansion: translate a C source's macro
    invocations with a macros.json dictionary (deterministic hits, recorded
    LLM proposals for unknowns) and synthesize + Z3-prove the V2 model."""
    from pipeline.macro_semantics import synthesize_v2_from_macros

    def run():
        path = _workspace_path(source)
        return synthesize_v2_from_macros(
            path, _workspace_path(dictionary), provider=provider,
            project_root=path.parent, verify=True)
    return _guarded(run)


def verify_weak_memory(source: str, memory_model: str = "x86_tso") -> dict[str, Any]:
    """OS lane 2: weak-memory barrier correspondence under an x86-TSO or
    ARMv8 profile — every cross-thread access must sit under an explicit
    ordering primitive; the full RC11/herd7 claim is honestly judge-pending."""
    from pipeline.weak_memory import barrier_correspondence
    return _guarded(lambda: barrier_correspondence(
        _workspace_path(source), memory_model))


def verify_wcet(source: str, timing: dict[str, Any]) -> dict[str, Any]:
    """OS lane 3: deterministic WCET bound under a human-declared hardware
    cost model ({"max_cycles": N, "loop_bounds": {...}}); unbounded loops
    and missed deadlines fail closed (aiT remains judge-pending)."""
    from pipeline.realtime import wcet_bound
    return _guarded(lambda: wcet_bound(_workspace_path(source), timing))


def verify_liveness(domain: dict[str, Any]) -> dict[str, Any]:
    """OS lane 3: bounded liveness over a transition domain — no non-ready
    sink states; scheduler fairness is the human-accepted assumption
    (SPIN LTL remains judge-pending)."""
    from pipeline.realtime import liveness_check
    return _guarded(lambda: liveness_check(domain))


def verify_dma(source: str, memory_map: dict[str, Any],
               contracts: dict[str, Any]) -> dict[str, Any]:
    """OS lane 4: DMA isolation by deterministic range disjointness — each
    dma_map/ioremap window inside its device contract and outside every
    kernel pool (the CN/Kani hardware memory model remains judge-pending)."""
    from pipeline.dma_isolation import dma_isolation as run_dma
    return _guarded(lambda: run_dma(_workspace_path(source),
                                    memory_map, contracts))


def extract_intrusive_list(source: str, capacity: int) -> dict[str, Any]:
    """OS lane 5: abstract the intrusive list_head dialect to a bounded size
    counter (0 <= size <= capacity); capacity is a human declaration — the
    tool never guesses it."""
    from pipeline.os_patterns import extract_intrusive_list as run_extract

    def run() -> dict[str, Any]:
        path = _workspace_path(source)
        return run_extract(path.read_text(encoding="utf-8"), capacity)
    return _guarded(run)


def resolve_callbacks(source: str) -> dict[str, Any]:
    """OS lane 5: resolve file_operations-style callback registrations;
    extern targets are named unresolved, and machines_for_extraction lists
    only the callbacks whose bodies live in the source."""
    from pipeline.os_patterns import resolve_callbacks as run_resolve
    return _guarded(lambda: run_resolve(
        _workspace_path(source).read_text(encoding="utf-8")))


def submit_work_item(
        work_item_id: str, base_revision: str, objective: str, workflow: str,
        variant: dict[str, str], allowed_paths: list[str],
        protected_paths: list[str], acceptance_plan_ref: str,
        authority_ref: str, deliverables: list[str],
        requested_effects: list[str], resource_budget: dict[str, int],
        worker_id: str | None = None,
        parent_work_item_id: str | None = None) -> dict[str, Any]:
    """Submit a bounded proposal to an operator-approved A2A worker.

    The authority reference is resolved server-side. Worker completion never
    means that the patch was accepted, proved, signed, or merged.
    """
    effects = (
        "workspace_read", "service_state_write", "remote_worker_dispatch")
    admission = authorize_mcp_invocation(
        "submit_work_item", mode="submit", language="none",
        backend="a2a-1.0", effects=effects)
    if not admission.admitted:
        return admission.rejection()
    try:
        from pipeline.a2a_coordination import WorkItem, current_git_revision

        require_mcp_effect(admission, "workspace_read")
        if current_git_revision(Path.cwd()) != base_revision:
            raise ValueError("base_revision does not identify the current checkout")
        item = WorkItem(
            work_item_id=work_item_id,
            base_revision=base_revision,
            objective=objective,
            workflow=workflow,
            variant=variant,
            allowed_paths=tuple(allowed_paths),
            protected_paths=tuple(protected_paths),
            acceptance_plan_ref=acceptance_plan_ref,
            authority_ref=authority_ref,
            deliverables=tuple(deliverables),
            requested_effects=tuple(requested_effects),
            resource_budget=resource_budget,
            parent_work_item_id=parent_work_item_id,
        )
        require_mcp_effect(admission, "service_state_write")
        coordinator = _configured_a2a_coordinator(create_state=True)
        require_mcp_effect(admission, "remote_worker_dispatch")
        record = coordinator.submit(item, _a2a_principal(), worker_id)
        return _coordination_response(record, admission)
    except Exception as exc:
        return _coordination_error(exc)


def get_work_item(
        work_item_id: str, refresh: bool = True) -> dict[str, Any]:
    """Read an authorized work item, optionally refreshing it over A2A."""
    effects = (("service_state_read", "service_state_write",
                "remote_worker_dispatch") if refresh else ("service_state_read",))
    admission = authorize_mcp_invocation(
        "get_work_item", mode="refresh" if refresh else "local",
        language="none", backend="a2a-1.0", effects=effects)
    if not admission.admitted:
        return admission.rejection()
    try:
        require_mcp_effect(admission, "service_state_read")
        coordinator = _configured_a2a_coordinator(create_state=False)
        if refresh:
            require_mcp_effect(admission, "remote_worker_dispatch")
            require_mcp_effect(admission, "service_state_write")
        record = coordinator.get(
            work_item_id, _a2a_principal(), refresh=refresh)
        return _coordination_response(record, admission)
    except Exception as exc:
        return _coordination_error(exc)


def get_work_artifacts(work_item_id: str) -> dict[str, Any]:
    """Return digest-bound worker artifact references, never implicit files."""
    admission = authorize_mcp_invocation(
        "get_work_artifacts", mode="artifacts", language="none",
        backend="a2a-1.0", effects=("service_state_read",))
    if not admission.admitted:
        return admission.rejection()
    try:
        require_mcp_effect(admission, "service_state_read")
        coordinator = _configured_a2a_coordinator(create_state=False)
        result = coordinator.artifacts(work_item_id, _a2a_principal())
        inconsistent = result.get("coordination_status") == "inconsistent"
        return {
            **result,
            "status": ("COORDINATION_INCONSISTENT" if inconsistent
                       else result["status"]),
            "claim": "NO_PROOF",
            "request_satisfied": not inconsistent,
            "coordination_inconsistent": inconsistent,
            "implementation_accepted": False,
            "mcp_admission": admission.summary(),
        }
    except Exception as exc:
        return _coordination_error(exc)


def cancel_work_item(work_item_id: str) -> dict[str, Any]:
    """Cancel a principal-owned work item and its remote A2A task."""
    effects = (
        "service_state_read", "service_state_write", "remote_worker_dispatch")
    admission = authorize_mcp_invocation(
        "cancel_work_item", mode="cancel", language="none",
        backend="a2a-1.0", effects=effects)
    if not admission.admitted:
        return admission.rejection()
    try:
        require_mcp_effect(admission, "service_state_read")
        coordinator = _configured_a2a_coordinator(create_state=False)
        require_mcp_effect(admission, "remote_worker_dispatch")
        require_mcp_effect(admission, "service_state_write")
        record = coordinator.cancel(work_item_id, _a2a_principal())
        return _coordination_response(record, admission)
    except Exception as exc:
        return _coordination_error(exc)


def doctor_environment() -> dict[str, Any]:
    """Report hash-bound judge readiness without minting evidence."""
    from pipeline.doctor import inspect_environment
    report = inspect_environment()
    report["judge_manifest"] = {
        item["name"]: item for item in report["capabilities"]}
    return report


def _strict_dispatch_guard(tool: Callable[..., dict[str, Any]]):
    """Reject undeclared MCP routes before their workflow imports or dispatches."""
    @wraps(tool)
    def guarded(*args, **kwargs):
        if _strict_mcp_isolation_enabled():
            return _isolation_unsupported(tool.__name__)
        return tool(*args, **kwargs)
    return guarded


def _install_strict_dispatch_guards() -> None:
    """Apply the registry policy to direct calls as well as server registration.

    FastMCP's default catalogue contains only supported routes, but keeping the
    call boundary guarded prevents an adapter or future registration path from
    reaching an undeclared backend indirectly.
    """
    from pipeline.capability_registry import mcp_capabilities

    for capability in mcp_capabilities():
        if capability.mcp_isolation != "unsupported":
            continue
        name = capability.mcp_tool or ""
        tool = globals().get(name)
        if not callable(tool):
            raise RuntimeError(f"registered MCP binding is missing: {name}")
        globals()[name] = _strict_dispatch_guard(tool)


_install_strict_dispatch_guards()


def create_server():
    if FastMCP is None:
        raise RuntimeError("MCP SDK is not installed; install with: pip install 'formalspecgen[mcp]'")
    server = FastMCP("FormalSpecGen")
    from pipeline.capability_registry import mcp_capabilities
    for capability in mcp_capabilities(
            strict_isolation=_strict_mcp_isolation_enabled()):
        tool = globals().get(capability.mcp_tool or "")
        if not callable(tool):
            raise RuntimeError(f"registered MCP binding is missing: {capability.mcp_tool}")
        server.tool()(tool)
    return server


if __name__ == "__main__":
    create_server().run()
