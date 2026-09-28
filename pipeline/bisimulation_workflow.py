# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded source/mapping preflight with controlled optional result publication."""
import hashlib
import json
import os
from pathlib import Path
import stat

from . import bisimulation
from .bounded_inputs import BoundedInputError, CaptureBudget, capture, input_directory, input_path
from .mcp_artifacts import MCPArtifactError, publish_new_artifacts
from .mcp_policy import MCPPolicyViolation
from .workflow_contracts import BisimulationWorkflowRequest, WorkflowContext, bind_workflow_result


BISIMULATION_BUDGET = {"max_input_bytes": 4 * 1024 * 1024, "max_input_files": 256,
                       "max_path_depth": 32, "max_traversal_entries": 4096,
                       "max_result_bytes": 8 * 1024 * 1024}

def _capture_inputs(request: BisimulationWorkflowRequest, context: WorkflowContext) -> list[tuple[str, Path, bytes]]:
    limits = {**BISIMULATION_BUDGET, **context.resource_budget}
    budget = CaptureBudget(limits["max_input_bytes"], limits["max_input_files"])
    captured = []
    def read(path: Path, role: str, parent_fd: int):
        captured.append((role, path, capture(path.name, parent_fd, context, budget)))
    for role, value in (("baseline", request.baseline), ("mapping", request.mapping)):
        path, relative = input_path(value, context)
        with input_directory(relative, context) as parent_fd:
            read(path, role, parent_fd)
    path, relative = input_path(request.refactored, context)
    with input_directory(relative, context) as parent_fd:
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        try:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                names = []
                with os.scandir(fd) as entries:
                    for index, entry in enumerate(entries, 1):
                        if index > limits["max_traversal_entries"]:
                            raise BoundedInputError("INPUT_TRAVERSAL_LIMIT_EXCEEDED", "too many candidate directory entries")
                        if entry.name.endswith(".java"):
                            if len(names) >= budget.remaining_files:
                                raise BoundedInputError("INPUT_LIMIT_EXCEEDED", "aggregate file allowance exceeded")
                            names.append(entry.name)
                if not names:
                    raise BoundedInputError("INVALID_INPUT", "candidate directory has no top-level .java sources")
                for name in sorted(names):
                    read(path / name, "refactored", fd)
            elif stat.S_ISREG(os.fstat(fd).st_mode):
                read(path, "refactored", parent_fd)
            else:
                raise BoundedInputError("INVALID_INPUT", "candidate must be a regular file or directory")
        finally:
            os.close(fd)
    return captured


def _mapping(content: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate mapping key")
            result[key] = value
        return result
    return json.loads(content.decode("utf-8"), object_pairs_hook=pairs)


def _source_text(content: bytes) -> str:
    # Preserve the old read_text universal-newline semantics while retaining
    # original byte identities in the manifest and never reopening the source.
    return content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def run_bisimulation_workflow(request: BisimulationWorkflowRequest, context: WorkflowContext,
                              *, output_root: Path | None = None, export_key: str | None = None) -> dict:
    result = {"claim": "NO_PROOF", "request_satisfied": False,
              "behavior_equivalence_proved": False, "heap_topology_equivalence_proved": False,
              "claim_limits": ["Mapping/class-name and lexical public-method checks only; not Java parsing or type checking.",
                               "Matching public signatures does not establish contract or behavioral preservation.",
                               "Directory candidates include top-level .java files only; no recursive project analysis."]}
    export_allowed = False
    limit = context.resource_budget.get("max_result_bytes", BISIMULATION_BUDGET["max_result_bytes"])
    def bound():
        value = bind_workflow_result(result, request, context.interface, context=context)
        if context.interface.value == "mcp":
            value["mcp_admission"] = context.authority.summary()
        return value
    try:
        context.require("workspace_read")
        if request.result_export is not None:
            context.require("workspace_write_new")
            if output_root is None or export_key is None:
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "export destination is required")
            key = Path(export_key)
            if key.is_absolute() or ".." in key.parts or not key.name:
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "unsafe export destination")
            destination = (output_root / key).resolve()
            inputs = [Path(value).resolve() for value in (request.baseline, request.mapping, request.refactored)]
            if destination in inputs or (inputs[2].is_dir() and inputs[2] in destination.parents):
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "export aliases an input or candidate directory")
            export_allowed = True
        captured = _capture_inputs(request, context)
        manifest = [{"role": role, "path": str(path), "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()} for role, path, data in captured]
        result["input_manifest"] = manifest
        result["input_manifest_sha256"] = hashlib.sha256(json.dumps(
            manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        baseline = captured[0][2]
        candidates = [data for role, _, data in captured if role == "refactored"]
        result.update(baseline_sha256=hashlib.sha256(baseline).hexdigest(),
                      refactored_sha256=hashlib.sha256(b"".join(candidates)).hexdigest(),
                      mapping_sha256=hashlib.sha256(captured[1][2]).hexdigest(),
                      refactored_sources=[str(path) for role, path, _ in captured if role == "refactored"])
        result.update(bisimulation.check_bisimulation_sources(_source_text(baseline),
            "\n".join(_source_text(data) for data in candidates), _mapping(captured[1][2])))
        result["request_satisfied"] = result["status"] == "BISIMULATION_PREFLIGHT_READY"
        if len(json.dumps(bound()).encode()) > limit:
            result = {"status": "BISIMULATION_INPUT_INVALID", "claim": "NO_PROOF", "request_satisfied": False,
                      "code": "RESULT_LIMIT_EXCEEDED", "behavior_equivalence_proved": False,
                      "heap_topology_equivalence_proved": False}
    except (OSError, ValueError, RuntimeError, MCPPolicyViolation) as exc:
        result.update(status="BISIMULATION_INPUT_INVALID", request_satisfied=False,
                      code=getattr(exc, "code", "input_unavailable" if isinstance(exc, OSError) else "INVALID_INPUT"),
                      message=str(exc))
    if export_allowed:
        try:
            context.require("workspace_write_new")
            published = publish_new_artifacts(output_root, {export_key: json.dumps(
                bound(), indent=2, ensure_ascii=False) + "\n"}, context.authority, max_total_bytes=limit)
            result["result_export"] = {"status": "COMMITTED", "artifacts": published}
        except (OSError, ValueError, MCPPolicyViolation) as exc:
            result.update(status="RESULT_EXPORT_FAILED", claim="NO_PROOF", request_satisfied=False,
                          code=getattr(exc, "code", "PUBLICATION_FAILED"), message=str(exc),
                          result_export={"status": "FAILED"})
    return bound()
