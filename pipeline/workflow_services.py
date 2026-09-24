# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Application services used by terminal and MCP transport adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import code_documentation, java_inspection
from .verification_policy import decide_verification
from .workflow_contracts import (
    DocumentationWorkflowRequest,
    InspectionWorkflowRequest,
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
