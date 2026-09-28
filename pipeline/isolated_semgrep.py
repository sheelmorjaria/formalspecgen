# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Local-rule SAST infrastructure; no registry fallback or security proof claim."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from . import config, cwe_registry
from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .execution import ExecutionPolicy, ExecutionRequest, SourceSnapshot, StrictSandboxExecutor
from .workflow_contracts import WorkflowContext


@dataclass(frozen=True)
class SemgrepScanRequest:
    source: str
    timeout_s: int = 60

    def __post_init__(self):
        if not isinstance(self.source, str) or not self.source or "\0" in self.source:
            raise ValueError("source must be a nonempty path")
        if type(self.timeout_s) is not int or self.timeout_s <= 0:
            raise ValueError("scan timeout must be a positive integer")


_CEILINGS = {
    "max_input_bytes": 4 * 1024**2, "max_input_files": 2, "max_path_depth": 32,
    "max_rule_bytes": 1024**2, "max_execution_seconds": 60,
    "max_memory_bytes": 2 * 1024**3, "max_processes": 64,
    "max_output_bytes": 1024**2, "max_file_bytes": 64 * 1024**2,
    "max_workspace_bytes": 128 * 1024**2, "max_temporary_bytes": 64 * 1024**2,
    "max_findings": 4096,
}


def _local_rules(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("rules must be a regular local file")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("local rules exceed the input allowance")
    content.decode("utf-8")
    return content


def _json_output(output: str) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate Semgrep output key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("non-finite Semgrep output number")
    value = json.loads(output, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(value, dict):
        raise ValueError("expected a Semgrep JSON object")
    return value


def _interpret(data: dict, target: str, relative: str, lines: int, maximum: int) -> dict:
    findings = data.get("results")
    errors, paths = data.get("errors"), data.get("paths")
    skipped_rules = data.get("skipped_rules")
    version = data.get("version")
    if (not isinstance(findings, list) or len(findings) > maximum or
            not isinstance(errors, list) or not isinstance(paths, dict) or
            not isinstance(skipped_rules, list) or
            not isinstance(version, str) or not version.strip()):
        raise ValueError("missing, malformed or excessive Semgrep output fields")
    if (not isinstance(paths.get("scanned"), list) or
            not isinstance(paths.get("skipped", []), list)):
        raise ValueError("invalid scan coverage")
    normalized = []
    for item in findings:
        if not isinstance(item, dict) or item.get("path") != target:
            raise ValueError("finding does not refer to the captured source")
        rule, start, extra = item.get("check_id"), item.get("start"), item.get("extra")
        if (not isinstance(rule, str) or not rule or not isinstance(start, dict) or
                not isinstance(extra, dict) or type(start.get("line")) is not int or
                not 1 <= start["line"] <= lines or
                not isinstance(extra.get("message"), str) or
                extra.get("severity") not in {"INFO", "WARNING", "ERROR"}):
            raise ValueError("malformed Semgrep finding")
        entry = cwe_registry.by_rule_id(rule)
        normalized.append({"tool": "semgrep", "rule_id": rule, "source": relative,
                           "line": start["line"], "message": extra["message"],
                           "severity": extra["severity"], "cwe": entry.cwe_id if entry else None,
                           "unmapped_rule_id": entry is None})
    complete = not errors and not skipped_rules and paths["scanned"] == [target] and not paths.get("skipped")
    return {"findings": normalized, "errors": errors, "version": version,
            "skipped_rules": skipped_rules,
            "scan_complete": complete, "scanned_sources": [relative] if complete else []}


def run_isolated_semgrep(
        request: SemgrepScanRequest, context: WorkflowContext, *,
        rules_path: Path | None = None, executable: str | None = None,
        executor: StrictSandboxExecutor | None = None) -> dict:
    """Capture a workspace source and operator-selected local rules, then scan.

    ``rules_path`` and ``executable`` belong to trusted deployment configuration,
    not a model's action arguments. No provider, autofix, upload or registry use.
    """
    context.require("workspace_read")
    context.require("external_execution")
    result = {"status": "SAST_FAILED", "claim": "NO_PROOF", "request_satisfied": False,
              "scan_complete": False, "findings": [], "errors": [], "version": None,
              "execution_observations": [], "snapshot_manifest": [],
              "snapshot_manifest_sha256": None, "source": request.source,
              "claim_limits": ["configured_local_rules_only", "single_captured_source",
                               "findings_require_review", "clean_is_not_security_proof"],
              "admission": context.authority.summary()}
    try:
        limits = {}
        for name, ceiling in _CEILINGS.items():
            value = context.resource_budget.get(name, ceiling)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
            limits[name] = min(value, ceiling)
        if limits["max_input_files"] < 2:
            raise ValueError("source and local rules require two input files")
        # Use the attenuated limits also at the shared capture boundaries.
        child = WorkflowContext(context.interface, context.authority, context.workspace_root,
                                context.required_effects, context.output_root, limits)
        source, relative = input_path(request.source, child)
        rule_name = {".java": "java_custom.yml", ".c": "c_custom.yml", ".h": "c_custom.yml",
                     ".cpp": "c_custom.yml", ".cc": "c_custom.yml"}.get(source.suffix.lower())
        if rule_name is None:
            result.update(status="SAST_UNSUPPORTED", message="unsupported source language for local SAST")
            return result
        budget = CaptureBudget(limits["max_input_bytes"], limits["max_input_files"])
        with input_directory(relative, child) as directory:
            content = capture(relative.name, directory, child, budget)
        text = content.decode("utf-8")
        selected = rules_path if rules_path is not None else config.resource_path("security", rule_name)
        rules = _local_rules(Path(selected), min(limits["max_rule_bytes"], budget.remaining_bytes))
        binary = shutil.which(executable or os.environ.get("SEMGREP_BIN", "semgrep"))
        if not binary:
            result.update(status="TOOL_MISSING", message="configured Semgrep executable is unavailable")
            return result
        binary = Path(binary).resolve()
        tool_root = binary.parent.parent if binary.parent.name == "bin" else binary.parent
        if (context.workspace_root.is_relative_to(tool_root) or source.is_relative_to(tool_root)):
            raise ValueError("Semgrep runtime mount must not expose the workspace or original source")
        # Semgrep's native telemetry client initializes a TLS authenticator
        # even when metrics/version checks are disabled. Supply only the public
        # system CA bundle, not /etc/ssl (which can contain private keys).
        ca_bundle = Path("/etc/ssl/certs/ca-certificates.crt")
        runtime_paths = (tool_root,) + ((ca_bundle,) if ca_bundle.is_file() else ())
        policy = ExecutionPolicy(
            timeout_s=min(request.timeout_s, limits["max_execution_seconds"]),
            **{name: limits[name] for name in ("max_memory_bytes", "max_processes",
               "max_output_bytes", "max_file_bytes", "max_workspace_bytes", "max_temporary_bytes")})
        with tempfile.TemporaryDirectory(prefix="formalspecgen-isolated-semgrep-") as directory:
            root = Path(directory)
            logical = f"source/{relative.name}"
            target = f"/input/{logical}"
            snapshot = SourceSnapshot.create(root / "snapshot", {logical: content, "rules/rules.yml": rules})
            result.update(source=relative.as_posix(), snapshot_manifest=list(snapshot.manifest),
                          snapshot_manifest_sha256=snapshot.manifest_sha256)
            command = (str(binary), "scan", "--oss-only", "--metrics=off", "--disable-version-check",
                       "--disable-nosem", "--no-git-ignore", "--no-rewrite-rule-ids", "--error",
                       "--json", "--quiet", "--jobs", "1", "--timeout", str(int(policy.timeout_s)),
                       "--max-memory", str(max(1, policy.max_memory_bytes // 1024**2)),
                       "--max-target-bytes", str(limits["max_input_bytes"]),
                       "--config", "/input/rules/rules.yml", target)
            context.require("external_execution")
            observation = (executor or StrictSandboxExecutor()).execute(ExecutionRequest(
                tool="semgrep", command=command, snapshot=snapshot, workspace=root / "workspace",
                policy=policy, readonly_paths=runtime_paths))
            result["execution_observations"].append(observation.as_dict())
            if (observation.policy_compliance != "ENFORCED" or observation.timed_out or
                    observation.output_truncated or observation.status not in {"COMPLETED", "TOOL_FAILED"}):
                result["status"] = "SAST_EXECUTION_FAILED"
                return result
            try:
                result.update(_interpret(_json_output(observation.output), target, relative.as_posix(),
                                         max(1, len(text.splitlines())), limits["max_findings"]))
            except (ValueError, RecursionError, TypeError) as exc:
                result.update(status="SAST_INVALID_OUTPUT", message=str(exc))
                return result
            if observation.exit_code not in {0, 1} or (observation.exit_code == 1 and not result["findings"]):
                result["scan_complete"] = False
            complete = result["scan_complete"]
            result.update(status=("SAST_FINDINGS" if result["findings"] else "SAST_CLEAN") if complete
                          else "SAST_INCOMPLETE", request_satisfied=complete)
        return result
    except (OSError, ValueError) as exc:
        result.update(status="SAST_PREPARATION_OR_EXECUTION_FAILED", message=str(exc),
                      request_satisfied=False, scan_complete=False)
        return result
