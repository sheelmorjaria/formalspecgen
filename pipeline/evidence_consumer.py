# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Read-only, bounded consumption of existing RunLedger evidence."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
from .bounded_inputs import (
    BoundedInputError as EvidenceInputError, CaptureBudget as _CaptureBudget,
    capture as _capture, input_directory as _input_directory, input_path as _input_path,
)

from .lifecycle import RunLedger
from .mcp_policy import MCPPolicyViolation
from .workflow_contracts import WORKFLOW_CONTRACT_SCHEMA, WorkflowContext


EVIDENCE_BUDGET = {"max_input_bytes": 8 * 1024 * 1024, "max_input_files": 256,
                   "max_path_depth": 32}


@dataclass(frozen=True)
class EvidenceWorkflowRequest:
    manifest: str
    operation: str = "validate"
    expected_sha256: str | None = None
    comparison_manifest: str | None = None
    comparison_expected_sha256: str | None = None
    source: str | None = None

    def __post_init__(self):
        if not isinstance(self.operation, str) or self.operation not in {"validate", "explain", "diff"}:
            raise ValueError("evidence operation must be validate, explain or diff")
        if not isinstance(self.manifest, str) or not self.manifest:
            raise ValueError("manifest path is required")
        for name in ("expected_sha256", "comparison_expected_sha256"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", value)):
                raise ValueError(f"{name} must be a full lowercase SHA-256 digest")
        if self.operation == "diff":
            if not isinstance(self.comparison_manifest, str) or not self.comparison_manifest:
                raise ValueError("diff requires comparison_manifest")
        elif self.comparison_manifest is not None or self.comparison_expected_sha256 is not None:
            raise ValueError("comparison inputs are only supported by diff")
        if self.source is not None and (not isinstance(self.source, str) or not self.source):
            raise ValueError("source must be a nonempty path")
        if self.source is not None and self.operation == "diff":
            raise ValueError("source checking is supported only by validate and explain")

    def required_effects(self):
        return ("workspace_read",)

    def as_dict(self):
        return {"schema": "formalspecgen-evidence-request-v1", **asdict(self)}


def _name(value):
    if not isinstance(value, str) or value in {"", ".", "..", "manifest.json"} \
            or Path(value).name != value or "/" in value or "\\" in value:
        raise EvidenceInputError("INVALID_INVENTORY", "artifact names must be distinct flat filenames")
    return value


def _reject_nonfinite(value: str):
    raise ValueError(f"non-finite JSON value is not supported: {value}")


def _recorded_source_binding(terminal: dict, captured: dict[str, bytes]) -> dict:
    """Interpret only the current verification receipt, never follow its paths."""
    request = terminal.get("workflow_request")
    digest = terminal.get("source_sha256")
    if terminal.get("claim_policy_version") != "verification-policy-v1" or not isinstance(request, dict) \
            or request.get("schema") != WORKFLOW_CONTRACT_SCHEMA or request.get("workflow") != "verify" \
            or not isinstance(request.get("source"), str) or not request["source"] \
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise EvidenceInputError("UNSUPPORTED_SOURCE_BINDING", "receipt has no supported primary-source binding")
    proofs = [json.loads(data, parse_constant=_reject_nonfinite) for name, data in captured.items() if name != "run.json"]
    matching = [record for record in proofs if record.get("state") == "PROOF"
                and isinstance(record.get("details"), dict)
                and record["details"].get("workflow_request") == request]
    if len(matching) != 1 or not isinstance(matching[0].get("evidence"), dict):
        raise EvidenceInputError("INCONSISTENT_SOURCE_BINDING", "receipt must bind one verification proof record")
    evidence = matching[0]["evidence"]
    stages = terminal.get("execution_stages")
    if evidence.get("source_sha256") != digest or evidence.get("source_path") != request["source"] \
            or not isinstance(stages, list) or not stages or evidence.get("execution_stages") != stages:
        raise EvidenceInputError("INCONSISTENT_SOURCE_BINDING", "terminal and proof-stage source bindings disagree")
    name = Path(request["source"]).name
    if name in {"", ".", ".."} or "\x00" in request["source"]:
        raise EvidenceInputError("UNSUPPORTED_SOURCE_BINDING", "recorded primary source path is malformed")
    records = []
    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get("snapshot_files"), list):
            raise EvidenceInputError("UNSUPPORTED_SOURCE_BINDING", "source snapshot observations are absent")
        for record in stage["snapshot_files"]:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise EvidenceInputError("INCONSISTENT_SOURCE_BINDING", "malformed source snapshot record")
            if record.get("path") in {name, f"reviewed/{name}"}:
                records.append(record)
    if not records:
        raise EvidenceInputError("UNSUPPORTED_SOURCE_BINDING", "primary source snapshot is absent")
    size = records[0].get("size")
    if type(size) is not int or size < 0 or any(record.get("sha256") != digest or type(record.get("size")) is not int or record.get("size") != size for record in records):
        raise EvidenceInputError("INCONSISTENT_SOURCE_BINDING", "primary source snapshot identities disagree")
    return {"recorded_path": request["source"], "sha256": digest, "size": size}


def inspect_evidence(request: EvidenceWorkflowRequest, context: WorkflowContext) -> dict:
    """Never run a tool, follow artifact links, publish, or upgrade recorded claims."""
    limits = {**EVIDENCE_BUDGET, **context.resource_budget}
    budget = _CaptureBudget(limits["max_input_bytes"], limits["max_input_files"])
    if request.operation != "diff":
        return _inspect_one(request, context, budget)
    baseline = _inspect_one(EvidenceWorkflowRequest(
        request.manifest, expected_sha256=request.expected_sha256), context, budget)
    # This initial reference is presentation only. Expansion and input checks
    # happen inside _inspect_one after the baseline succeeds.
    comparison_path = Path(request.comparison_manifest)
    if not comparison_path.is_absolute():
        comparison_path = context.workspace_root / comparison_path
    result = {
        "schema": "formalspecgen-evidence-inspection-v1", "claim": "NO_PROOF",
        "request": {**request.as_dict(), "manifest": baseline["request"]["manifest"],
                    "comparison_manifest": str(comparison_path)},
        "status": "EVIDENCE_COMPARISON_REJECTED", "request_satisfied": False,
        "integrity": {"status": "NOT_ESTABLISHED", "valid": False},
        "authenticity": {"status": "NOT_ASSESSED"},
        "applicability": {"status": "NOT_ASSESSED"},
        "assurance": {"status": "NOT_ASSESSED"},
        "baseline": baseline,
        "comparison": {"status": "NOT_CHECKED", "request_satisfied": False},
        "limitations": [*baseline["limitations"],
            "Comparison is of recorded data and artifact bytes, not semantic or behavioral equivalence.",
            "Both ledgers share one aggregate capture budget; inputs are not reopened for comparison."],
    }
    if not baseline["request_satisfied"]:
        result["code"] = "BASELINE_EVIDENCE_REJECTED"
        return result
    comparison = _inspect_one(EvidenceWorkflowRequest(
        request.comparison_manifest, expected_sha256=request.comparison_expected_sha256), context, budget)
    result["comparison"] = comparison
    result["request"]["comparison_manifest"] = comparison["request"]["manifest"]
    if not comparison["request_satisfied"]:
        result["code"] = "COMPARISON_EVIDENCE_REJECTED"
        return result
    left = {item["path"]: item for item in baseline["captured_inputs"]}
    right = {item["path"]: item for item in comparison["captured_inputs"]}
    before, after = baseline["recorded_terminal"], comparison["recorded_terminal"]
    # Compare JSON representations so bool/int or missing/null cannot collapse
    # into equal values through Python's equality rules.
    changed = []
    try:
        for key in sorted(before.keys() | after.keys()):
            old = json.dumps(before.get(key), sort_keys=True, allow_nan=False)
            new = json.dumps(after.get(key), sort_keys=True, allow_nan=False)
            if key not in before or key not in after or old != new:
                changed.append({"field": key, "baseline_present": key in before,
                                "comparison_present": key in after,
                                "baseline": before.get(key), "comparison": after.get(key)})
    except (ValueError, RecursionError) as exc:
        result.update(code="INVALID_COMPARISON_DATA", message=str(exc))
        return result
    result.update(status="EVIDENCE_COMPARED", request_satisfied=True,
                  integrity={"status": "VALID", "valid": True},
                  differences={
                      "manifest_bytes_equal": baseline["manifest_sha256"] == comparison["manifest_sha256"],
                      "artifacts_added": [right[name] for name in sorted(right.keys() - left.keys())],
                      "artifacts_removed": [left[name] for name in sorted(left.keys() - right.keys())],
                      "artifacts_modified": [{"path": name, "baseline": left[name], "comparison": right[name]}
                                             for name in sorted(left.keys() & right.keys()) if left[name] != right[name]],
                      "artifacts_unchanged": [name for name in sorted(left.keys() & right.keys()) if left[name] == right[name]],
                      "recorded_terminal_changes": changed,
                  })
    return result


def _inspect_one(request: EvidenceWorkflowRequest, context: WorkflowContext,
                 budget: _CaptureBudget) -> dict:
    result = {
        "schema": "formalspecgen-evidence-inspection-v1", "claim": "NO_PROOF",
        "request": request.as_dict(), "request_satisfied": False,
        "integrity": {"status": "NOT_CHECKED"},
        "manifest_binding": {"status": "NOT_REQUESTED"},
        "authenticity": {"status": "NOT_ASSESSED"},
        "applicability": {"status": "NOT_ASSESSED"},
        "assurance": {"status": "NOT_ASSESSED"},
        "limitations": [
            "Integrity means internal consistency, not trusted authorship or verification success.",
            "The expected digest is supplied by the caller, not authenticated by this service.",
            "Current source, dependencies, toolchain and policy applicability are not checked.",
            "Signatures, external artifact references and assurance requirements are not checked.",
        ],
    }
    stack = ExitStack()
    try:
        # Keep lexical path components until descriptor-based traversal. Resolving
        # links before opening would discard the information needed to reject them.
        path, relative = _input_path(request.manifest, context)
        result["request"] = {**request.as_dict(), "manifest": str(path)}
        if request.source is not None:
            source_path = Path(request.source).expanduser()
            result["request"]["source"] = str(source_path if source_path.is_absolute() else context.workspace_root / source_path)
        directory_fd = stack.enter_context(_input_directory(relative, context))

        def capture(name):
            return _capture(name, directory_fd, context, budget)

        manifest_bytes = capture(relative.name)
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        result["manifest_sha256"] = digest
        if request.expected_sha256 is not None:
            matches = digest == request.expected_sha256
            result["manifest_binding"] = {"status": "MATCH" if matches else "MISMATCH"}
            if not matches:
                raise EvidenceInputError("MANIFEST_DIGEST_MISMATCH", "manifest differs from the caller's expected digest")
        manifest = json.loads(manifest_bytes, parse_constant=_reject_nonfinite)
        if not isinstance(manifest, dict) or manifest.get("schema") != "formalspecgen-evidence-manifest-v1":
            raise EvidenceInputError("UNSUPPORTED_MANIFEST", "expected a RunLedger v1 manifest")
        inventory = manifest.get("artifacts")
        if not isinstance(inventory, list) or not inventory:
            raise EvidenceInputError("INVALID_INVENTORY", "artifact inventory is absent or malformed")
        if len(inventory) > budget.remaining_files:
            raise EvidenceInputError("INPUT_LIMIT_EXCEEDED", "aggregate file allowance exceeded")
        names = []
        for item in inventory:
            if not isinstance(item, dict):
                raise EvidenceInputError("INVALID_INVENTORY", "malformed artifact record")
            name = _name(item.get("path"))
            if name == relative.name or name in names:
                raise EvidenceInputError("INVALID_INVENTORY", "duplicate or self-referencing artifact")
            names.append(name)
        captured = {name: capture(name) for name in names}
        checked = RunLedger.validate_captured(manifest, captured.__getitem__)
        result["integrity"] = {key: value for key, value in checked.items() if key != "terminal"}
        result["captured_inputs"] = [{"path": name, "sha256": hashlib.sha256(content).hexdigest(),
                                      "size": len(content)} for name, content in captured.items()]
        result["status"] = "EVIDENCE_VALID" if checked["valid"] else "EVIDENCE_INVALID"
        result["request_satisfied"] = checked["valid"]
        if checked["valid"]:
            terminal = checked["terminal"]
            result["recorded_terminal"] = terminal
            if request.operation == "explain":
                result["explanation"] = {
                    "run_id": checked["run_id"], "artifact_count": len(captured),
                    "recorded_status": terminal.get("final_status", "UNKNOWN"),
                    "recorded_claim": terminal.get("claim", "NO_PROOF"),
                    "recorded_claim_limits": terminal.get("claim_limits", {}),
                    "interpretation": "These are recorded assertions, not independently established proof claims.",
                }
            if request.source is not None:
                # Integrity remains available even if the separately requested
                # source check fails. Never infer read authority from receipt paths.
                result["request_satisfied"] = False
                result["applicability"] = {"status": "NOT_ESTABLISHED", "scope": "primary-source-bytes-only"}
                binding = _recorded_source_binding(terminal, captured)
                source_path, source_relative = _input_path(request.source, context)
                with _input_directory(source_relative, context) as source_fd:
                    content = _capture(source_relative.name, source_fd, context, budget)
                actual = {"path": str(source_path), "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
                matches = actual["sha256"] == binding["sha256"] and actual["size"] == binding["size"]
                result["source_binding"] = {"status": "MATCH" if matches else "MISMATCH",
                                            "recorded": binding, "captured": actual}
                result["applicability"] = {
                    "status": "SOURCE_MATCH_ONLY" if matches else "SOURCE_CHANGED",
                    "scope": "primary-source-bytes-only", "full_applicability_established": False,
                    "unchecked": ["dependencies", "toolchain", "assumptions", "admission-policy", "source-context"],
                }
                result["limitations"][2] = "Only primary-source bytes were compared; dependencies, toolchain, assumptions and full applicability are not checked."
                result.update(status="EVIDENCE_SOURCE_MATCH" if matches else "EVIDENCE_SOURCE_CHANGED",
                              request_satisfied=matches)
    except (OSError, ValueError, RuntimeError, MCPPolicyViolation) as exc:
        result.update(request_satisfied=False,
                      status="EVIDENCE_SOURCE_CHECK_REJECTED" if request.source is not None and result["integrity"].get("valid") else
                      "EVIDENCE_INCOMPLETE" if isinstance(exc, FileNotFoundError) else "EVIDENCE_INVALID",
                      code=getattr(exc, "code", "INVALID_INPUT"), message=str(exc))
        if result["integrity"]["status"] == "NOT_CHECKED":
            result["integrity"]["reason"] = "Input rejected before integrity validation completed."
    finally:
        stack.close()
    return result
