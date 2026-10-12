# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Captured reviewed V2 inputs -> deterministic JML -> isolated Java ESC.

Generation never executes a compiler or provider. Implementation checks retain
the native claim only; this service does not establish source/model refinement
or authenticate the reviewed-domain artifact's human origin.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import uuid

from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .domain_validation_preparation import (
    CapturedDomainCandidate, DOMAIN_PREPARATION_LIMITS, prepare_captured_domain_candidate,
)
from .domain_v2 import DomainSpecV2
from .domain_v2_promotion import ReviewedDomainSpecV2
from .domain_v2_publication import EvidenceEnvelope
from .domain_validation_identity import assess_domain_validation_applicability
from .implementation import IMPLEMENT_SYSTEM, trusted_surface_hash, trusted_surface_matches
from .isolated_verification import execute_isolated_verification
from .llm import LLMError, _chat_fn, provider_response_limit, strip_fence
from .mcp_artifacts import publish_new_artifacts
from .v2_jml_serializer import render_class
from .verification_policy import decide_result
from .workflow_contracts import WorkflowContext


REVIEWED_JAVA_SCHEMA = "formalspecgen-reviewed-java-v1"
REVIEWED_JAVA_LIMITS = {"max_input_bytes": 4 * 1024**2, "max_input_files": 5,
    "max_path_depth": 32, "max_result_bytes": 8 * 1024**2,
    "max_source_bytes": 128 * 1024, "max_provider_bytes": 256 * 1024}


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


@dataclass(frozen=True)
class ReviewedJavaRequest:
    reviewed_domain: str
    validation_evidence: str
    domain_candidate: str
    operation: str = "draft"
    scaffold: str | None = None
    candidate: str | None = None
    provider: str = "ollama"
    model: str | None = None
    requirement: str = ""
    out_file: str | None = None

    def __post_init__(self):
        if self.operation not in {"draft", "implement"}:
            raise ValueError("unsupported reviewed Java operation")
        for name in ("reviewed_domain", "validation_evidence", "domain_candidate"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name) or "\0" in getattr(self, name):
                raise ValueError(f"{name} is required")
        if not isinstance(self.requirement, str) or len(self.requirement.encode()) > 16 * 1024:
            raise ValueError("requirement exceeds the text limit")
        if self.provider not in {"glm", "openai", "ollama"}:
            raise ValueError("unsupported provider")
        if self.model is not None and (not isinstance(self.model, str) or not self.model.strip() or len(self.model.encode()) > 256):
            raise ValueError("model must be bounded nonempty text")
        if self.operation == "draft" and (self.scaffold is not None or self.candidate is not None or self.model is not None):
            raise ValueError("draft generation does not accept implementation or provider model inputs")
        if self.operation == "implement" and not self.scaffold:
            raise ValueError("implementation requires the canonical scaffold")
        for name in ("scaffold", "candidate", "out_file"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value or "\0" in value):
                raise ValueError(f"{name} must be a nonempty path")
        if self.candidate is not None and self.model is not None:
            raise ValueError("a supplied candidate does not use a provider model")

    def required_effects(self):
        effects = ["workspace_read", "workspace_write_new"]
        if self.operation == "implement":
            effects.extend(("external_execution", "evidence_publication"))
            if self.candidate is None:
                effects.append("provider_access")
        return tuple(effects)


def run_reviewed_java(request: ReviewedJavaRequest, context: WorkflowContext, *, execute=None, chat=None) -> dict:
    """Capture once, check identities, prepare privately, publish without replacement."""
    result = {"schema": REVIEWED_JAVA_SCHEMA, "status": "FAIL", "claim": "NO_PROOF",
        "request_satisfied": False, "source_refinement_proved": False,
        "review_authenticity_established": False, "operation": request.operation}
    try:
        # Validate the entire effect plan before reading, provider access or execution.
        for effect in request.required_effects():
            context.require(effect)
        if context.output_root is None:
            raise ValueError("designated output root is required")
        limits = {key: min(context.resource_budget.get(key, ceiling), ceiling)
                  for key, ceiling in REVIEWED_JAVA_LIMITS.items()}
        if any(type(value) is not int or value <= 0 for value in limits.values()):
            raise ValueError("reviewed Java limits must be positive integers")
        budget = CaptureBudget(limits["max_input_bytes"], limits["max_input_files"])
        captured = {}

        def read(label, value):
            path, relative = input_path(value, context)
            with input_directory(relative, context) as fd:
                content = capture(relative.name, fd, context, budget)
            captured[label] = content
            return path, content

        _, reviewed_bytes = read("reviewed_domain", request.reviewed_domain)
        reviewed = ReviewedDomainSpecV2.model_validate_json(reviewed_bytes)
        candidate_path, candidate_bytes = read("domain_candidate", request.domain_candidate)
        prepared = prepare_captured_domain_candidate(CapturedDomainCandidate(
            str(candidate_path), candidate_bytes, tuple(DOMAIN_PREPARATION_LIMITS.items())))
        original = DomainSpecV2.model_validate_json(prepared.candidate_json)
        if original.review_status != "unreviewed":
            raise ValueError("original domain candidate must be unreviewed")
        semantic = reviewed.model_dump(mode="json", include=set(DomainSpecV2.model_fields))
        semantic["review_status"] = "unreviewed"
        if semantic != original.model_dump(mode="json") or reviewed.accepted_candidate_sha256 != prepared.candidate_sha256:
            raise ValueError("reviewed domain does not match the captured candidate")
        _, validation_bytes = read("validation_evidence", request.validation_evidence)
        envelope = EvidenceEnvelope.model_validate_json(validation_bytes)
        applicability = assess_domain_validation_applicability(envelope, candidate_bytes)
        if not applicability.applicable:
            result["applicability"] = applicability.as_dict()
            raise ValueError("validation evidence requires revalidation")
        if (reviewed.accepted_evidence_sha256 != envelope.evidence_sha256
                or reviewed.accepted_validation_artifact_sha256 != _sha(validation_bytes)
                or reviewed.accepted_applicability_sha256 != applicability.expected_context_sha256):
            raise ValueError("reviewed domain validation bindings differ; revalidation and promotion required")
        # This initial profile is intentionally sequential and atomic.
        if reviewed.concurrency is not None or reviewed.execution_model is not None:
            raise ValueError("this Java profile supports sequential atomic domains only")
        code = render_class(reviewed)
        if len(code.encode()) > limits["max_source_bytes"]:
            raise ValueError("generated contract exceeds source limit")
        name = f"{reviewed.domain_name}.java"
        key = PurePosixPath(request.out_file or f"reviewed-java/{uuid.uuid4().hex}/{name}")
        if key.is_absolute() or ".." in key.parts or key.name != name:
            raise ValueError(f"output must be a relative path ending in {name}")
        contract = code.encode()
        result.update(status="CANONICAL_CONTRACT", request_satisfied=True,
            workflow_request={key: value for key, value in vars(request).items()},
            authority=context.authority.summary(), resource_limits=limits,
            transformation="DETERMINISTIC_V2_TO_JML", applicability=applicability.as_dict(),
            accepted_candidate_sha256=prepared.candidate_sha256,
            contract_sha256=_sha(contract), trusted_surface_sha256=trusted_surface_hash(code),
            requirement_sha256=_sha(request.requirement.encode()),
            implementation_identity={file: _sha((Path(__file__).parent / file).read_bytes())
                for file in ("reviewed_java_workflow.py", "v2_jml_serializer.py", "java_contracts.py", "verification_policy.py")},
            claim_limits=["no_specification_adequacy", "no_source_model_refinement", "no_concurrency_proof",
                "review_artifact_integrity_is_not_reviewer_authentication"])
        output = contract
        if request.operation == "implement":
            _, scaffold = read("scaffold", request.scaffold)
            if scaffold != contract:
                raise ValueError("scaffold differs from the deterministic reviewed contract")
            if request.candidate is not None:
                _, output = read("implementation", request.candidate)
                generated = output.decode("utf-8")
                provenance = {"kind": "caller-supplied"}
            else:
                with provider_response_limit(limits["max_provider_bytes"]):
                    raw, model, _ = (chat or _chat_fn(request.provider))([
                        {"role": "system", "content": IMPLEMENT_SYSTEM},
                        {"role": "user", "content": "Trusted JML scaffold:\n```java\n" + code + "\n```"}], request.model, 0.2)
                if not isinstance(raw, str):
                    raise ValueError("provider must return text")
                generated = strip_fence(raw)
                output = generated.encode()
                provenance = {"kind": "provider", "provider": request.provider, "model": str(model)[:256]}
                captured["implementation"] = output
            if len(output) > limits["max_source_bytes"]:
                raise ValueError("implementation exceeds source limit")
            matches, differences = trusted_surface_matches(code, generated)
            if not matches:
                result["surface_diff"] = differences
                raise ValueError("implementation changed the trusted contract or API")
            with tempfile.TemporaryDirectory(prefix="formalspecgen-reviewed-java-") as private:
                source = Path(private) / name
                source.write_bytes(output)
                detailed = (execute or execute_isolated_verification)(source, mode="esc", backend="prusti")
            decision = decide_result(detailed.payload, tool="openjml", mode="esc")
            result.update(decision, implementation_sha256=_sha(output), implementation_provenance=provenance,
                execution_stages=[item.as_dict() for item in detailed.observations], output=detailed.output)
            result["tool_identities"] = []
            for stage in result["execution_stages"]:
                if stage.get("command"):
                    executable = Path(stage["command"][0])
                    if executable.is_file():
                        result["tool_identities"].append({"path": str(executable), "sha256": _sha(executable.read_bytes())})
            # A native claim requires a retained enforced observation of these bytes.
            bound = any(stage.get("policy_compliance") == "ENFORCED" and
                any(item.get("sha256") == _sha(output) and item.get("path") in {name, f"reviewed/{name}"}
                    for item in stage.get("snapshot_files", [])) for stage in result["execution_stages"])
            if not bound:
                result.update(status="EXECUTION_UNBOUND", claim="NO_PROOF", request_satisfied=False)
        result["input_identities"] = {label: {"sha256": _sha(content), "size": len(content)} for label, content in captured.items()}
        receipt_key = str(key) + ".receipt.json"
        artifacts = {str(key): output, receipt_key: _json(result)}
        for label, content in captured.items():
            artifacts[str(key) + f".inputs/{label}"] = content
        publication = publish_new_artifacts(context.output_root, artifacts, context.authority,
            max_total_bytes=limits["max_result_bytes"])
        return {**result, "publication": publication, "code_file": publication[str(key)]["path"],
            "evidence_file": publication[receipt_key]["path"]}
    except (OSError, ValueError, RuntimeError, RecursionError, LLMError) as exc:
        return {**result, "status": "FAIL", "claim": "NO_PROOF", "request_satisfied": False,
            "code": getattr(exc, "code", "REVIEWED_JAVA_REJECTED"), "message": str(exc)}
