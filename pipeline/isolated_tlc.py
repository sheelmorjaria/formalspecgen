# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded TLC execution for generated models, not source-level proof/admission.

Tool paths are operator configuration, never model-proposed arguments. Both
stages use the same captured jar and model bytes and retain actual observations.
The caller owns model generation, source correspondence and final publication.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path

from . import config
from .execution import ExecutionPolicy, ExecutionRequest, SourceSnapshot, StrictSandboxExecutor
from .isolated_verification import _java_configuration_paths
from .workflow_contracts import WorkflowContext


@dataclass(frozen=True)
class TlcModelRequest:
    module_name: str
    tla: str
    cfg: str
    timeout_s: int = 120

    def __post_init__(self) -> None:
        if (not isinstance(self.module_name, str) or
                not re.fullmatch(r"[A-Z][A-Za-z0-9]{0,127}", self.module_name)):
            raise ValueError("unsafe TLA+ module name")
        if not isinstance(self.tla, str) or not isinstance(self.cfg, str):
            raise ValueError("TLA and CFG must be generated text")
        if type(self.timeout_s) is not int or self.timeout_s <= 0:
            raise ValueError("TLC timeout must be a positive integer")


def _limit(context: WorkflowContext, name: str, ceiling: int) -> int:
    value = context.resource_budget.get(name, ceiling)
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return min(value, ceiling)


def _capture_jar(path: Path, limit: int) -> bytes:
    # A FIFO/device must not block the controller, and the final pathname may
    # not be a symlink. The captured bytes, not this mutable path, are executed.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("TLC jar must be a regular operator-configured file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("TLC jar exceeds max_tool_bytes")
    return data


def run_isolated_tlc(
        request: TlcModelRequest, context: WorkflowContext, *,
        tlc_jar: str | None = None, java: str | None = None,
        executor: StrictSandboxExecutor | None = None) -> dict:
    """Check one captured TLA/CFG pair with no host-execution fallback.

    Successful execution is deliberately NO_PROOF at this infrastructure layer:
    it establishes a model-check observation, not source correspondence, reviewed
    bounds, invariant adequacy, authenticated tool provenance or publication.
    """
    context.require("external_execution")  # before tool reads or preparation
    result = {
        "status": "TLC_FAILED", "claim": "NO_PROOF", "model_check_passed": False,
        "request_satisfied": False, "execution_observations": [],
        "snapshot_manifest": [], "snapshot_manifest_sha256": None,
        "version": None, "exit_status": None,
        "claim_limits": ["generated_model_only", "no_source_correspondence_proof",
                         "caller_must_bind_bounds_assumptions_and_publish_evidence"],
        "admission": context.authority.summary(),
    }
    started = time.monotonic()
    try:
        model_limit = _limit(context, "max_input_bytes", 4 * 1024 * 1024)
        if len(request.tla) + len(request.cfg) > model_limit:
            raise ValueError("generated model exceeds max_input_bytes")
        tla, cfg = request.tla.encode("utf-8"), request.cfg.encode("utf-8")
        if len(tla) + len(cfg) > model_limit:
            raise ValueError("generated model exceeds max_input_bytes")
        total_seconds = min(request.timeout_s, _limit(context, "max_execution_seconds", 120))
        policy = ExecutionPolicy(
            timeout_s=total_seconds,
            max_memory_bytes=_limit(context, "max_memory_bytes", 2 * 1024**3),
            max_processes=_limit(context, "max_processes", 64),
            max_output_bytes=_limit(context, "max_output_bytes", 1024**2),
            max_file_bytes=_limit(context, "max_file_bytes", 64 * 1024**2),
            max_workspace_bytes=_limit(context, "max_workspace_bytes", 128 * 1024**2),
            max_temporary_bytes=_limit(context, "max_temporary_bytes", 64 * 1024**2))
        if any(value <= 0 for value in (
                total_seconds, policy.max_memory_bytes, policy.max_processes,
                policy.max_output_bytes, policy.max_file_bytes,
                policy.max_workspace_bytes, policy.max_temporary_bytes)):
            raise ValueError("TLC execution requires nonzero resource allowances")
        binary = shutil.which(java or config.JAVA_BIN)
        if not binary:
            result["status"] = "TOOL_MISSING"
            result["message"] = "configured Java executable is unavailable"
            return result
        binary = Path(binary).resolve()
        java_home = binary.parent.parent
        jar = _capture_jar(Path(tlc_jar or config.TLC_JAR),
                           _limit(context, "max_tool_bytes", 32 * 1024**2))
        with tempfile.TemporaryDirectory(prefix="formalspecgen-isolated-tlc-") as directory:
            root = Path(directory)
            snapshot = SourceSnapshot.create(root / "snapshot", {
                f"{request.module_name}.tla": tla, f"{request.module_name}.cfg": cfg,
                "tool/tla2tools.jar": jar})
            result["snapshot_manifest"] = list(snapshot.manifest)
            result["snapshot_manifest_sha256"] = snapshot.manifest_sha256
            command = (str(binary), "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=2",
                       f"-Xmx{max(1, policy.max_memory_bytes // (2 * 1024**2))}m",
                       "-jar", "/input/tool/tla2tools.jar")
            stages = (
                ("tlc-provenance", (*command, "-help")),
                ("tlc-model-check", (*command, "-workers", "1", "-metadir", "/work/states",
                                     "-config", f"/input/{request.module_name}.cfg",
                                     f"/input/{request.module_name}.tla")))
            remaining_output = policy.max_output_bytes
            for stage, invocation in stages:
                remaining = total_seconds - (time.monotonic() - started)
                if remaining <= 0 or remaining_output <= 0:
                    result["status"] = "RESOURCE_BUDGET_EXHAUSTED"
                    return result
                context.require("external_execution")
                observation = (executor or StrictSandboxExecutor()).execute(ExecutionRequest(
                    tool=stage, command=invocation, snapshot=snapshot,
                    workspace=root / stage,
                    policy=replace(policy, timeout_s=min(10, remaining) if stage ==
                                   "tlc-provenance" else remaining,
                                   max_output_bytes=remaining_output),
                    readonly_paths=(java_home, *_java_configuration_paths(str(java_home))),
                    environment={"JAVA_HOME": str(java_home)}))
                result["execution_observations"].append(observation.as_dict())
                result["exit_status"] = observation.exit_code
                remaining_output -= len(observation.output.encode("utf-8"))
                if (observation.policy_compliance != "ENFORCED" or
                        observation.status not in {"COMPLETED", "TOOL_FAILED"} or
                        observation.timed_out or observation.output_truncated):
                    result["status"] = "TLC_EXECUTION_FAILED"
                    return result
                if stage == "tlc-provenance":
                    version = re.search(r"^TLC2 Version ([0-9][^\r\n]*)",
                                        observation.output, re.MULTILINE)
                    # Supported TLC -help prints the banner and may exit 1.
                    if observation.exit_code not in {0, 1} or not version:
                        result["status"] = "TOOL_VERSION_UNAVAILABLE"
                        return result
                    result["version"] = version.group(1).strip()
                elif (observation.exit_code == 0 and observation.status == "COMPLETED" and
                      "Model checking completed. No error has been found." in observation.output):
                    result.update(status="TLC_MODEL_CHECK_PASSED", model_check_passed=True,
                                  request_satisfied=True)
        return result
    except (OSError, ValueError) as exc:
        result.update(status="TLC_PREPARATION_OR_EXECUTION_FAILED", message=str(exc),
                      request_satisfied=False, model_check_passed=False)
        return result
