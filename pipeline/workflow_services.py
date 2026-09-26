# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Application services used by terminal and MCP transport adapters."""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import code_documentation, java_inspection
from .isolated_verification import (
    IsolatedVerificationResult,
    execute_isolated_verification,
)
from .verification_policy import decide_result, decide_verification
from .verify import VerificationExecutionResult, verify_files_detailed
from .workflow_contracts import (
    DocumentationWorkflowRequest,
    InspectionWorkflowRequest,
    RefactorWorkflowRequest,
    VerificationWorkflowRequest,
    WorkflowContext,
)


@dataclass(frozen=True)
class VerificationServiceResult:
    payload: dict[str, Any]
    backend_result: Any


@dataclass(frozen=True)
class DocumentationServiceResult:
    payload: dict[str, Any]
    bundle: code_documentation.DocumentationBundle | None


@dataclass(frozen=True)
class RefactorServiceResult:
    payload: dict[str, Any]
    stages: tuple[dict[str, Any], ...]
    inputs: dict[str, Any]


@dataclass(frozen=True)
class _CapturedRefactorSource:
    """One source read exactly once before hashing and private snapshotting."""

    path: Path
    content: bytes


def run_java_verification(
        request: VerificationWorkflowRequest, context: WorkflowContext,
        execute: Callable[[Path, str], Any]) -> VerificationServiceResult:
    """Run and interpret one Java verification through an injected backend.

    The backend adapter decides how the tool is executed; the shared service
    owns request interpretation, effect checks and verdict construction.
    """
    if request.language not in {"java", "jml"}:
        raise ValueError("Java verification service requires Java/JML input")
    source = context.resolve_input(request.source, must_exist=False)
    context.require("external_execution")
    backend_result = execute(source, request.mode)
    if isinstance(backend_result, tuple):
        exit_code, output = backend_result
    else:
        exit_code = int(backend_result.exit_code)
        output = str(backend_result.output)
    payload = {
        **decide_verification(
            tool="openjml", mode=request.mode,
            exit_code=int(exit_code), output=str(output)),
        "exit_code": int(exit_code),
        "mode": request.mode,
        "language": "java",
        "source": str(source),
        "output": str(output),
    }
    return VerificationServiceResult(payload, backend_result)


def run_verification(
        request: VerificationWorkflowRequest, context: WorkflowContext,
        *, execute: Callable[..., IsolatedVerificationResult] | None = None
        ) -> VerificationServiceResult:
    """Execute and interpret every supported verification route uniformly."""
    source = context.resolve_input(request.source, must_exist=False)
    if request.language not in {"java", "jml", "rust", "c", "cpp"}:
        payload = {
            "status": "UNSUPPORTED_LANGUAGE", "exit_code": 2,
            "claim": "NO_PROOF", "request_satisfied": False,
            "message": f"unsupported source language: {request.language}",
        }
        return VerificationServiceResult(
            payload, IsolatedVerificationResult(payload))
    if request.language in {"c", "cpp"} and request.mode != "esc":
        payload = {
            "status": "UNSUPPORTED_MODE", "exit_code": 2,
            "claim": "NO_PROOF", "request_satisfied": False,
            "language": request.language,
            "message": f"{request.language} verification supports only esc mode",
        }
        return VerificationServiceResult(
            payload, IsolatedVerificationResult(payload))
    context.require("external_execution")
    backend_result = (execute or execute_isolated_verification)(
        source, mode=request.mode, backend=request.backend)
    raw = dict(backend_result.payload)
    tool = request.effective_backend
    decision = decide_result(raw, tool=tool, mode=request.mode)
    payload = {
        **raw, **decision,
        "exit_code": backend_result.exit_code,
        "mode": request.mode,
        "language": request.language,
        "source": str(source),
        "output": backend_result.output,
        "execution": (backend_result.observation.as_dict()
                      if backend_result.observation else None),
        "execution_stages": [item.as_dict() for item in backend_result.observations],
    }
    return VerificationServiceResult(payload, backend_result)


def run_java_inspection(
        request: InspectionWorkflowRequest,
        context: WorkflowContext) -> dict[str, Any]:
    """Inspect one Java source after enforcing the shared read boundary."""
    if request.language not in {"java", "jml"}:
        return {
            "status": "UNSUPPORTED_LANGUAGE", "claim": "NO_PROOF",
            "request_satisfied": False,
            "message": f"inspection does not support {request.language}",
        }
    source = context.resolve_input(request.source)
    limit = context.resource_budget.get("max_input_bytes")
    try:
        with source.open("rb") as handle:
            encoded = handle.read(limit + 1 if limit is not None else -1)
    except OSError as exc:
        return {
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "source_unavailable", "message": str(exc),
        }
    if limit is not None and len(encoded) > limit:
        return {
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "INPUT_LIMIT_EXCEEDED",
            "message": f"source exceeds the inspection limit of {limit} bytes",
        }
    try:
        text = encoded.decode("utf-8")
    except UnicodeError:
        return {
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "source_unavailable", "message": "source is not valid UTF-8",
        }
    return java_inspection.inspect_java_source(text, source)


def run_documentation_preparation(
        request: DocumentationWorkflowRequest,
        context: WorkflowContext, *,
        resolve_model: Callable[[str, str | None], str] | None = None,
        generate: Callable[..., code_documentation.DocumentationNarrative] | None =
        None) -> DocumentationServiceResult:
    """Prepare documentation in memory through shared CLI/MCP semantics.

    Reading and provider disclosure are enforced here. Publication remains an
    adapter concern because CLI replacement behavior and strict MCP no-replace
    publication are deliberately different policies.
    """
    if request.language != "java":
        return DocumentationServiceResult({
            "status": "UNSUPPORTED_LANGUAGE", "claim": "NO_PROOF",
            "request_satisfied": False,
            "message": f"documentation does not support {request.language}",
        }, None)
    source = context.resolve_input(request.source)
    limit = context.resource_budget.get("max_input_bytes")
    try:
        with source.open("rb") as handle:
            encoded = handle.read(limit + 1 if limit is not None else -1)
    except OSError as exc:
        return DocumentationServiceResult({
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "input_unavailable", "message": str(exc),
        }, None)
    if limit is not None and len(encoded) > limit:
        return DocumentationServiceResult({
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "INPUT_LIMIT_EXCEEDED",
            "message": f"source exceeds the documentation limit of {limit} bytes",
        }, None)
    try:
        text = encoded.decode("utf-8")
    except UnicodeError:
        return DocumentationServiceResult({
            "status": "FAIL", "claim": "NO_PROOF",
            "code": "input_unavailable", "message": "source is not valid UTF-8",
        }, None)

    extraction = code_documentation.extract_documentation_model(source, text)
    if isinstance(extraction, dict):
        return DocumentationServiceResult(extraction, None)

    narrative = None
    narrative_source = "disabled"
    provider_observation = None
    if request.provider is not None:
        context.require("provider_access")
        selected_model = (resolve_model or (lambda _provider, value: value or ""))(
            request.provider, request.model)
        try:
            narrative_generator = generate or code_documentation.generate_narrative_strict
            generated = narrative_generator(
                extraction.payload, request.provider, selected_model or None)
        except Exception as exc:
            return DocumentationServiceResult({
                "status": "FAIL", "claim": "NO_PROOF",
                "code": "PROVIDER_FAILED", "message": str(exc),
                "provider": {
                    "status": "FAILED", "provider": request.provider,
                    "requested_model": request.model,
                    "selected_model": selected_model or None,
                    "fallback": False, "request_count": 1,
                },
            }, None)
        response_limit = context.resource_budget.get("max_provider_response_bytes")
        response_size = len(str(generated.content).encode("utf-8"))
        if response_limit is not None and response_size > response_limit:
            return DocumentationServiceResult({
                "status": "FAIL", "claim": "NO_PROOF",
                "code": "PROVIDER_RESULT_LIMIT_EXCEEDED",
                "message": "provider narrative exceeds the configured result limit",
            }, None)
        narrative = generated.content
        narrative_source = "provider"
        provider_observation = {
            "status": "COMPLETED", "provider": request.provider,
            "requested_model": request.model,
            "selected_model": selected_model or None,
            "used_model": generated.model,
            "usage": generated.usage,
            "fallback": False, "request_count": 1,
            "disclosed_source_sha256": extraction.digest,
        }

    bundle = code_documentation.build_documentation_bundle(
        extraction, source, narrative=narrative,
        narrative_source=narrative_source)
    payload = dict(bundle.result)
    if provider_observation is not None:
        payload["provider"] = provider_observation
    return DocumentationServiceResult(payload, bundle)


def run_refactor_verification(
        request: RefactorWorkflowRequest, context: WorkflowContext, *,
        execute_native: Callable[..., IsolatedVerificationResult] | None = None,
        execute_java: Callable[[tuple[Path, ...], str], VerificationExecutionResult] | None =
        None) -> RefactorServiceResult:
    """Compare and independently verify an immutable baseline/candidate pair.

    The semantic gate remains authoritative for contract and proof-trust
    preservation.  This service prepares byte-identical private copies, injects
    observation-preserving strict verifier adapters, and retains every stage for
    publication by the transport adapter.
    """
    baseline = context.resolve_input(request.baseline)
    refactored = context.resolve_input(request.refactored)
    inputs, baseline_files, refactored_files = _refactor_inputs(
        baseline, refactored, context)
    if request.signing_intent:
        payload = {
            "status": "APPROVAL_REQUIRED", "claim": "NO_PROOF",
            "request_satisfied": False, "code": "human_signing_required",
            "message": (
                "detached signing requires an authenticated human approval "
                "workflow; no signing key is accepted by this service"),
            "approval": {
                "status": "REQUIRED", "action": "sign-refactor-evidence",
                "signing_authority_available": False,
            },
            "language": request.language,
            "backend": request.effective_backend,
            "input_manifest": inputs,
            "verification_stages": [],
        }
        return RefactorServiceResult(payload, (), inputs)

    context.require("external_execution")
    stages: list[dict[str, Any]] = []
    native_executor = execute_native or execute_isolated_verification

    def java_executor(
            files: tuple[Path, ...], mode: str) -> VerificationExecutionResult:
        return (execute_java or (
            lambda values, selected: verify_files_detailed(values, mode=selected)
        ))(files, mode)

    def runner(stage: str, files: tuple[Path, ...], language: str) -> dict:
        if language == "java":
            result = _run_java_refactor_stage(files, java_executor)
        else:
            backend = "prusti" if language == "rust" else request.effective_backend
            detailed = native_executor(files[0], mode="esc", backend=backend)
            tool = {"rust": "prusti", "c": "frama-c", "cpp": "esbmc"}[language]
            result = {
                **decide_result(detailed.payload, tool=tool, mode="esc"),
                "execution": (
                    detailed.observation.as_dict() if detailed.observation else None),
                "execution_stages": [item.as_dict() for item in detailed.observations],
                "output": detailed.output,
            }
        stage_result = {"stage": stage, "language": language, **result}
        stages.append(stage_result)
        return result

    from .refactor_gate import (
        verify_contract_preserving_refactor,
        verify_multifile_contract_refactor,
    )
    with tempfile.TemporaryDirectory(prefix="formalspecgen-refactor-") as directory:
        root = Path(directory)
        prepared_baseline = _prepare_refactor_files(
            root / "baseline", baseline_files, baseline)
        prepared_refactored = _prepare_refactor_files(
            root / "refactored", refactored_files,
            refactored if refactored.is_file() else None)
        if refactored.is_dir():
            gate = verify_multifile_contract_refactor(
                prepared_baseline, root / "refactored", runner=runner)
        else:
            assert prepared_refactored is not None
            gate = verify_contract_preserving_refactor(
                prepared_baseline, prepared_refactored, runner=runner)

    success = gate.get("status") == "VERIFIED"
    payload = {
        **gate,
        "claim": gate.get("claim", "NO_PROOF") if success else "NO_PROOF",
        "request_satisfied": success,
        "language": request.language,
        "backend": request.effective_backend,
        "input_manifest": inputs,
        "verification_stages": stages,
        "approval": None,
    }
    return RefactorServiceResult(payload, tuple(stages), inputs)


def _run_java_refactor_stage(
        files: tuple[Path, ...],
        execute: Callable[[tuple[Path, ...], str], VerificationExecutionResult]
        ) -> dict[str, Any]:
    observations = []
    check = execute(files, "check")
    if check.observation is not None:
        observations.append(check.observation.as_dict())
    checked = decide_verification(
        tool="openjml", mode="check", exit_code=check.exit_code,
        output=check.output)
    if not checked["request_satisfied"]:
        return {
            "status": "FAIL", "gate": "check", "claim": "NO_PROOF",
            "request_satisfied": False, "tool_status": checked["status"],
            "output": check.output, "execution": observations[-1] if observations else None,
            "execution_stages": observations,
        }
    esc = execute(files, "esc")
    if esc.observation is not None:
        observations.append(esc.observation.as_dict())
    proved = decide_verification(
        tool="openjml", mode="esc", exit_code=esc.exit_code,
        output=esc.output)
    if not proved["request_satisfied"]:
        return {
            "status": "FAIL", "gate": "esc", "claim": "NO_PROOF",
            "request_satisfied": False, "tool_status": proved["status"],
            "output": esc.output, "execution": observations[-1] if observations else None,
            "execution_stages": observations,
        }
    return {
        "status": "VERIFIED", "gate": "esc",
        "claim": "DEDUCTIVE_PROOF", "request_satisfied": True,
        "tool_status": proved["status"], "output": esc.output,
        "execution": observations[-1] if observations else None,
        "execution_stages": observations,
    }


def _refactor_inputs(
        baseline: Path, refactored: Path,
        context: WorkflowContext) -> tuple[
            dict[str, Any], tuple[_CapturedRefactorSource, ...],
            tuple[_CapturedRefactorSource, ...]]:
    if baseline.is_symlink() or refactored.is_symlink():
        raise ValueError("refactor inputs must not be symlinks")
    baseline_files = (baseline,)
    if refactored.is_dir():
        request_language = _language_for_path(baseline)
        if request_language not in {"java", "jml"}:
            raise ValueError("multifile refactoring supports Java/JML only")
        dependencies = tuple(sorted(
            path for path in baseline.parent.glob("*.java")
            if path != baseline and path.is_file()))
        baseline_files = (baseline, *dependencies)
        refactored_files = tuple(sorted(
            path for path in refactored.iterdir()
            if path.is_file() and path.suffix.lower() in {".java", ".jml"}))
        if not refactored_files:
            raise ValueError("refactored directory contains no Java/JML sources")
    elif refactored.is_file():
        refactored_files = (refactored,)
    else:
        raise FileNotFoundError(str(refactored))
    all_files = (*baseline_files, *refactored_files)
    if any(path.is_symlink() for path in all_files):
        raise ValueError("refactor source sets must not contain symlinks")
    captured_baseline = tuple(
        _CapturedRefactorSource(path, path.read_bytes()) for path in baseline_files)
    captured_refactored = tuple(
        _CapturedRefactorSource(path, path.read_bytes()) for path in refactored_files)
    limit = context.resource_budget.get("max_input_bytes")
    total = sum(
        len(source.content)
        for source in (*captured_baseline, *captured_refactored))
    if limit is not None and total > limit:
        raise ValueError(f"refactor inputs exceed the configured limit of {limit} bytes")
    return {
        "baseline": _source_records(captured_baseline, context.workspace_root),
        "refactored": _source_records(captured_refactored, context.workspace_root),
        "total_bytes": total,
    }, captured_baseline, captured_refactored


def _source_records(
        files: tuple[_CapturedRefactorSource, ...],
        workspace_root: Path) -> list[dict[str, Any]]:
    records = []
    for source in files:
        path, content = source.path, source.content
        try:
            logical = path.resolve().relative_to(workspace_root).as_posix()
        except ValueError:
            logical = path.name
        records.append({
            "path": logical, "name": path.name, "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    return records


def _prepare_refactor_files(
        root: Path, files: tuple[_CapturedRefactorSource, ...],
        primary: Path | None) -> Path | None:
    root.mkdir(parents=True, exist_ok=False)
    prepared_primary = None
    for source in files:
        destination = root / source.path.name
        destination.write_bytes(source.content)
        if primary is not None and source.path == primary:
            prepared_primary = destination
    return prepared_primary


def _language_for_path(path: Path) -> str:
    return {
        ".java": "java", ".jml": "jml", ".rs": "rust", ".c": "c",
        ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    }.get(path.suffix.lower(), "")
