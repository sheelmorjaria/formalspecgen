# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded, non-executing preparation and publication of review-only templates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .bounded_inputs import BoundedInputError, CaptureBudget, capture, input_directory, input_path
from .mcp_artifacts import MCPArtifactError, publish_new_artifacts
from .mcp_policy import MCPPolicyViolation
from .security_poc import _poc_for
from .workflow_contracts import SecurityTemplateWorkflowRequest, WorkflowContext, bind_workflow_result


SECURITY_TEMPLATE_BUDGET = {"max_input_bytes": 4 * 1024 * 1024, "max_input_files": 2,
    "max_path_depth": 32, "max_findings": 256, "max_matching_bytes": 16 * 1024 * 1024,
    "max_result_bytes": 8 * 1024 * 1024}
_SUFFIXES = {".java", ".rs", ".c", ".h", ".cpp", ".cc"}


def _findings(content: bytes, maximum: int) -> list[dict]:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate report key")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("non-finite report number")
    report = json.loads(content.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    findings = report.get("findings") if isinstance(report, dict) else report
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError("report must be a finding list or an object containing a finding list")
    if len(findings) > maximum:
        raise BoundedInputError("INPUT_LIMIT_EXCEEDED", "finding allowance exceeded")
    for item in findings:
        if any(key in item and not isinstance(item[key], str) for key in ("cwe", "type", "vc", "rule_id")):
            raise ValueError("finding selector fields must be strings")
    return findings


def run_security_template_workflow(request: SecurityTemplateWorkflowRequest, context: WorkflowContext,
        *, output_root: Path, artifact_dir: str, export_key: str | None) -> dict:
    limits = {**SECURITY_TEMPLATE_BUDGET, **context.resource_budget}
    result = {"status": "SECURITY_TEMPLATE_FAILED", "claim": "NO_PROOF", "request_satisfied": False,
        "target": request.target, "generated": [], "unsupported_findings": [], "exploit_proven": False,
        "executed": False, "review_status": "unreviewed",
        "claim_limits": ["Review-only templates; not compiled, executed, or accepted as regression tests.",
            "Report findings are untrusted assertions; their accuracy and applicability are not verified.",
            "Captured report/target identities establish provenance, not exploitability or correctness."]}
    export_allowed = False
    published_size = 0
    def bound():
        value = bind_workflow_result(result, request, context.interface, context=context)
        if context.interface.value == "mcp":
            value["mcp_admission"] = context.authority.summary()
        return value
    try:
        context.require("workspace_read")
        context.require("workspace_write_new")
        for name in (artifact_dir, export_key):
            if name is not None and (Path(name).is_absolute() or ".." in Path(name).parts or not name):
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "unsafe template destination")
        input_paths = {Path(request.report_path).resolve(), Path(request.target).resolve()}
        for name in (artifact_dir, export_key):
            if name is not None and (output_root / name).resolve() in input_paths:
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "template destination aliases an input")
        export_allowed = export_key is not None
        budget = CaptureBudget(limits["max_input_bytes"], limits["max_input_files"])
        captured = []
        for role, value in (("report", request.report_path), ("target", request.target)):
            path, relative = input_path(value, context)
            with input_directory(relative, context) as directory_fd:
                content = capture(relative.name, directory_fd, context, budget)
            captured.append((role, path, content))
        result["input_manifest"] = [{"role": role, "path": str(path), "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest()} for role, path, content in captured]
        result["input_manifest_sha256"] = hashlib.sha256(json.dumps(result["input_manifest"],
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        findings = _findings(captured[0][2], limits["max_findings"])
        target = captured[1][1]
        target_bytes = captured[1][2]
        source_text = target_bytes.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        if target.suffix.lower() not in _SUFFIXES:
            raise BoundedInputError("UNSUPPORTED_LANGUAGE", "no source templates for this target suffix")
        # Bound repeated legacy lexical scans as well as retained input/output.
        if len(target_bytes) * len(findings) > limits["max_matching_bytes"]:
            raise BoundedInputError("INPUT_LIMIT_EXCEEDED", "template matching allowance exceeded")
        prepared, artifacts = [], {}
        for index, finding in enumerate(findings, 1):
            # Native templates exist only for CWE-125; do not emit Java
            # snippets mislabeled as native source for other findings.
            template = (_poc_for(finding, target, index, source_text=source_text)
                if target.suffix.lower() == ".java" or finding.get("cwe") == "CWE-125" else None)
            if template is None:
                result["unsupported_findings"].append({"index": index, "finding": finding,
                    "reason": "no template for this language/finding combination"})
                continue
            name, code = template
            suffix = target.suffix.lower()
            name = name if name.endswith(suffix) else name + suffix
            key = str(Path(artifact_dir) / name)
            if export_key is not None and (output_root / key).resolve() == (output_root / export_key).resolve():
                export_allowed = False
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "result export aliases a template")
            if (output_root / key).resolve() in input_paths:
                raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "template aliases an input")
            artifacts[key] = code.encode("utf-8")
            prepared.append({"artifact": name, "publication_key": key, "finding_index": index, "finding": finding,
                "status": "POC_GENERATED", "executed": False, "review_status": "unreviewed"})
        result["status"] = "POCS_GENERATED" if prepared else "NO_SUPPORTED_POC"
        if artifacts:
            context.require("workspace_write_new")
            publication = publish_new_artifacts(output_root, artifacts, context.authority,
                                               max_total_bytes=limits["max_result_bytes"])
            published_size = sum(len(value) for value in artifacts.values())
            for entry in prepared:
                receipt = publication[entry["publication_key"]]
                result["generated"].append({**entry, "file": receipt["path"], "sha256": receipt["sha256"]})
            result["publication"] = {"status": "COMMITTED", "artifacts": publication}
            result["request_satisfied"] = True
        else:
            result["publication"] = {"status": "NOT_ATTEMPTED", "artifacts": {}}
    except (OSError, ValueError, RuntimeError, MCPPolicyViolation) as exc:
        result.update(status="SECURITY_TEMPLATE_FAILED", request_satisfied=False,
            code=getattr(exc, "code", "input_unavailable" if isinstance(exc, OSError) else "INVALID_INPUT"),
            message=str(exc))
    if export_allowed:
        try:
            context.require("workspace_write_new")
            exported = publish_new_artifacts(output_root, {export_key: json.dumps(bound(),
                indent=2, ensure_ascii=False) + "\n"}, context.authority,
                max_total_bytes=max(0, limits["max_result_bytes"] - published_size))
            result["result_export"] = {"status": "COMMITTED", "artifacts": exported}
        except (OSError, ValueError, MCPPolicyViolation) as exc:
            result.update(status="RESULT_EXPORT_FAILED", request_satisfied=False,
                code=getattr(exc, "code", "PUBLICATION_FAILED"), message=str(exc), result_export={"status": "FAILED"})
    return bound()
