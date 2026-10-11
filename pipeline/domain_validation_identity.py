# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Current domain-validation expectations, independent of recorded evidence."""
from __future__ import annotations

import hashlib
import importlib.metadata
import os
import shutil
import sys
from pathlib import Path

from . import __version__, config
from .domain_v2_evidence import canonical_sha256
from .isolated_tlc import _capture_jar
from .mcp_policy import authorize_mcp_invocation


DOMAIN_CONTEXT_SCHEMA = "formalspecgen-domain-validation-context-v1"
_COMPONENTS = ("domain_v2.py", "domain_v2_model.py", "domain_v2_tla.py",
    "domain_validation_preparation.py", "domain_validation_workflow.py",
    "domain_validation_identity.py", "isolated_tlc.py", "execution.py",
    "evidence_applicability.py", "domain_v2_publication.py", "domain_v2_evidence.py",
    "bounded_inputs.py", "workflow_contracts.py", "mcp_policy.py", "domain_v2_promotion.py")


def java_runtime_identity(binary: str | None = None) -> dict:
    """Identify the configured JVM and standard modules without executing it."""
    selected = binary or shutil.which(config.JAVA_BIN)
    if not selected:
        raise ValueError("configured Java runtime is unavailable")
    executable = Path(selected).resolve(strict=True)
    root = executable.parent.parent
    names = ("lib/modules", "lib/server/libjvm.so") if (root / "lib/modules").is_file() else (
        "jre/lib/rt.jar", "jre/lib/amd64/server/libjvm.so")
    files = {"bin/java": executable, "release": root / "release",
             **{name: root / name for name in names}}
    return {name: hashlib.sha256(_capture_jar(path, 256 * 1024**2)).hexdigest()
            for name, path in files.items()}


def read_validation_config(path: str | Path) -> dict:
    """Read a bounded, unambiguous operator configuration; never follow a final symlink."""
    from .evidence_consumer import _decode_evidence
    try:
        value = _decode_evidence(_capture_jar(Path(path), 16 * 1024))
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid validation configuration JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("validation configuration must be an object")
    return value


def domain_validation_context(source: bytes, *, limits: dict, timeout: int,
                              tlc_sha256: str | None = None, java_identity: dict | None = None) -> dict:
    """Bind the complete captured input tree, not an uncaptured project checkout.

    Implementation content identities work in installed wheels and dirty trees;
    package version alone cannot identify parser/translator semantics.
    """
    from .domain_validation_workflow import DomainValidationWorkflowRequest
    from .domain_validation_preparation import CapturedDomainCandidate, prepare_captured_domain_candidate
    from .execution import ExecutionPolicy
    from dataclasses import asdict
    root = Path(__file__).parent
    if len(source) > limits["max_input_bytes"]:
        raise ValueError("candidate exceeds applicability input allowance")
    prepared = prepare_captured_domain_candidate(CapturedDomainCandidate("candidate.input", source,
        tuple(sorted(limits.items()))))
    candidate_digest = prepared.candidate_sha256
    implementation = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                      for name in _COMPONENTS}
    policy = asdict(ExecutionPolicy(timeout_s=min(timeout, limits["max_execution_seconds"]),
        max_memory_bytes=min(limits.get("max_memory_bytes", 2 * 1024**3), 2 * 1024**3),
        max_processes=min(limits.get("max_processes", 64), 64),
        max_output_bytes=min(limits["max_output_bytes"], 1024**2)))
    for name in ("max_file_bytes", "max_workspace_bytes", "max_temporary_bytes"):
        policy[name] = min(limits.get(name, policy[name]), policy[name])
    admission = authorize_mcp_invocation("validate_domain", mode="validate", language="model",
        backend="tlc", effects=DomainValidationWorkflowRequest("candidate").required_effects())
    if not admission.admitted:
        raise ValueError("current bounded domain validation profile is not admitted")
    if tlc_sha256 is None:
        tlc_sha256 = hashlib.sha256(_capture_jar(Path(config.TLC_JAR),
            min(limits.get("max_tool_bytes", 32 * 1024**2), 32 * 1024**2))).hexdigest()
    sources = [{"path": "candidate.input", "size": len(source),
                "sha256": hashlib.sha256(source).hexdigest()}]
    summary = admission.summary()
    return {"schema": DOMAIN_CONTEXT_SCHEMA, "workflow": "validate-domain",
        "candidate_sha256": candidate_digest,
        "validation_schema_version": 2,
        "generated_models": prepared.summary()["generated_models"],
        "source_tree": {"scope": "captured-domain-inputs", "files": sources,
                        "sha256": canonical_sha256(sources)},
        "configuration": {"resource_limits": dict(limits), "execution_policy": policy},
        "implementation": {"package_version": __version__, "components": implementation,
            "python": sys.version,
            "platform": {"system": sys.platform, "machine": os.uname().machine, "kernel": os.uname().release},
            "dependencies": {name: importlib.metadata.version(name) for name in ("pydantic", "PyYAML")}},
        "tool": {"tlc_jar_sha256": tlc_sha256,
                 "java_runtime": java_identity if java_identity is not None else java_runtime_identity()},
        "admission": {key: summary[key] for key in ("profile_sha256", "admission_policy_version")}}


def assess_domain_validation_applicability(evidence, source: bytes, *, validation_config: dict | None = None):
    """Read-only domain adapter for the shared applicability evaluator.

    The caller supplies an integrity-checked envelope. Expected options come
    from the operator, not the envelope. No tool execution or promotion occurs.
    """
    from .domain_validation_workflow import DOMAIN_VALIDATION_LIMITS, DomainValidationWorkflowRequest
    from .evidence_applicability import evaluate_evidence_applicability
    options = {} if validation_config is None else validation_config
    if not isinstance(options, dict) or set(options) - {"timeout", "max_states", "max_transitions", "max_work_items"}:
        raise ValueError("unsupported validation configuration field")
    request = DomainValidationWorkflowRequest("candidate", **options)
    limits = dict(DOMAIN_VALIDATION_LIMITS)
    for key in ("max_states", "max_transitions", "max_work_items"):
        limits[key] = getattr(request, key)
    recorded = getattr(evidence.evidence, "applicability_context", None)
    expected = ({"schema": DOMAIN_CONTEXT_SCHEMA} if recorded is None else
                domain_validation_context(source, limits=limits, timeout=request.timeout))
    if recorded is not None:
        # An intact envelope can still assert a candidate different from its context.
        recorded = {**recorded, "envelope_candidate_sha256": evidence.evidence.candidate_sha256}
        expected = {**expected, "envelope_candidate_sha256": expected["candidate_sha256"]}
        recorded["envelope_generated_tla_sha256"] = evidence.evidence.generated_tla_sha256
        expected["envelope_generated_tla_sha256"] = next(identity["sha256"] for name, identity in
            expected["generated_models"].items() if name.endswith(".tla"))
    return evaluate_evidence_applicability(recorded, expected, evidence_sha256=evidence.evidence_sha256)
