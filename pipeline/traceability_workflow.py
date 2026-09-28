# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared traceability orchestration and controlled report publication."""
from __future__ import annotations

import json
from pathlib import Path

from .mcp_artifacts import MCPArtifactError, publish_new_artifacts
from .mcp_policy import MCPPolicyViolation
from .workflow_contracts import (
    TraceabilityWorkflowRequest, WorkflowContext, bind_workflow_result,
)
from .workflow_services import (
    _TRACEABILITY_SOURCE_SUFFIXES,
    bind_traceability_publication, run_traceability_generation,
)


TRACEABILITY_BUDGET = {
    "max_input_bytes": 8 * 1024 * 1024,
    "max_input_files": 514,
    "max_traversal_entries": 4096,
    "max_traversal_depth": 32,
    "max_result_bytes": 8 * 1024 * 1024,
    "max_matching_steps": 1_000_000,
}


def run_traceability_workflow(
        request: TraceabilityWorkflowRequest, context: WorkflowContext, *,
        output_root: Path, matrix_key: str, export_key: str) -> dict:
    """Publish the prepared matrix, then its result with authoritative paths.

    Negative outcomes may still publish the requested JSON result. If a later
    export fails, an already committed matrix stays available with its receipt,
    while the overall request is unsuccessful.
    """
    result: dict = {}
    export_allowed = False
    limit = context.resource_budget["max_result_bytes"]
    matrix_size = 0

    def bound() -> dict:
        value = bind_workflow_result(
            result, request, context.interface, context=context)
        if context.interface.value == "mcp":
            value["mcp_admission"] = context.authority.summary()
        return value

    def export_result() -> dict:
        context.require("workspace_write_new")
        return publish_new_artifacts(
            output_root, {export_key: json.dumps(
                bound(), indent=2, ensure_ascii=False) + "\n"},
            context.authority, max_total_bytes=max(0, limit - matrix_size))

    try:
        context.require("workspace_read")
        for name in (matrix_key, export_key):
            path = Path(name)
            if path.is_absolute() or ".." in path.parts or not path.name:
                raise MCPArtifactError(
                    "OUTPUT_SCOPE_VIOLATION", "unsafe traceability destination")
        matrix_path = output_root / matrix_key
        export_path = output_root / export_key
        inputs = {Path(request.domain), Path(request.requirements),
                  Path(request.source)}
        # Resolve only to compare aliases. Publication keeps the lexical paths
        # so the no-replace publisher can reject symlink components.
        for destination in (matrix_path, export_path):
            resolved = destination.resolve()
            if resolved in inputs or (
                    Path(request.source).is_dir()
                    and Path(request.source) in resolved.parents
                    and resolved.suffix.lower() in _TRACEABILITY_SOURCE_SUFFIXES):
                raise MCPArtifactError(
                    "OUTPUT_SCOPE_VIOLATION",
                    "traceability output aliases an input or source directory")
        if matrix_path.resolve() == export_path.resolve():
            raise MCPArtifactError(
                "OUTPUT_SCOPE_VIOLATION",
                "traceability Markdown and JSON destinations must differ")
        export_allowed = True
        service = run_traceability_generation(request, context)
        context.require("workspace_write_new")
        published = publish_new_artifacts(
            output_root, {matrix_key: service.markdown}, context.authority,
            max_total_bytes=limit)
        matrix_size = len(service.markdown)
        result = bind_traceability_publication(service, published, matrix_key)
        result["publication"] = {
            "status": "COMMITTED", "kind": "traceability-matrix",
            "artifacts": published,
        }
        exported = export_result()
        result["result_export"] = {
            "status": "COMMITTED", "kind": "traceability-result-export",
            "artifacts": exported,
        }
    except (OSError, ValueError, MCPPolicyViolation) as exc:
        message = str(exc)
        code = getattr(exc, "code", None)
        if code is None:
            code = ("path_outside_workspace"
                    if "inside the current workspace" in message else
                    "input_unavailable" if isinstance(exc, FileNotFoundError)
                    else message.split(":", 1)[0]
                    if message.split(":", 1)[0].isupper()
                    else "TRACEABILITY_GENERATION_FAILED")
        result.update({
            "status": "FAIL", "claim": "NO_PROOF",
            "request_satisfied": False, "code": code, "message": message,
        })
        if export_allowed:
            try:
                exported = export_result()
                result["result_export"] = {
                    "status": "COMMITTED", "kind": "traceability-result-export",
                    "artifacts": exported,
                }
            except (OSError, ValueError, MCPPolicyViolation) as export_exc:
                result["result_export"] = {
                    "status": "FAILED", "message": str(export_exc)}
    return bound()
