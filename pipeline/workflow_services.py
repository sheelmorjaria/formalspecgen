# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Application services used by terminal and MCP transport adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import java_inspection
from .verification_policy import decide_verification
from .workflow_contracts import (
    InspectionWorkflowRequest,
    VerificationWorkflowRequest,
    WorkflowContext,
)


@dataclass(frozen=True)
class VerificationServiceResult:
    payload: dict[str, Any]
    backend_result: Any


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
