# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""V2 promotion through the existing authenticated approval coordinator.

The publisher entry point runs under operator authority. MCP never supplies a
human decision, registry root, reviewer, policy file or signing credentials.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import tempfile
import uuid
from pathlib import Path

from .approval_service import (
    ApprovalService, ApprovalError, APPROVAL_REQUEST_SCHEMA, APPROVAL_RECEIPT_SCHEMA,
    _canonical_bytes, _write_once, _fsync_directory, _verify_detached_signature,
)
from .domain_v2_evidence import canonical_sha256
from .domain_v2_promotion import promote_validated_candidate
from .domain_validation_identity import read_validation_config
from .evidence_consumer import _decode_evidence

OPERATION_SCHEMA = "formalspecgen-domain-promotion-operation-v1"


def _capture(path: Path, limit: int = 8 * 1024**2) -> bytes:
    # MCP confines workspace inputs before calling this operator-side reader.
    # Open every ancestor by descriptor so a pathname race cannot follow links.
    from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
    from .workflow_contracts import WorkflowContext
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ApprovalError("ARTIFACT_UNAVAILABLE", "symlink or relative promotion input")
    context = WorkflowContext.for_cli(("workspace_read",), workspace_root=Path(path.anchor))
    _, relative = input_path(str(path), context)
    with input_directory(relative, context) as directory:
        return capture(relative.name, directory, context, CaptureBudget(limit, 1))


def _json(path: Path, schema: str | None = None) -> dict:
    return _object(_capture(path, 1024**2), schema)


def _object(content: bytes, schema: str | None = None) -> dict:
    try:
        value = _decode_evidence(content)
    except (UnicodeError, RecursionError) as exc:
        raise ApprovalError("APPROVAL_STATE_INVALID", "invalid promotion JSON") from exc
    if not isinstance(value, dict) or (schema and value.get("schema") != schema):
        raise ApprovalError("APPROVAL_STATE_INVALID", "invalid promotion state")
    return value


def _binding(path: Path, content: bytes) -> dict:
    return {"path": str(path), "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


def _check(binding: dict, limit: int = 8 * 1024**2) -> bytes:
    content = _capture(Path(binding["path"]), limit)
    if _binding(Path(binding["path"]), content) != binding:
        raise ApprovalError("APPROVED_ARTIFACT_CHANGED", "promotion input changed")
    return content


class DomainPromotionApprovalService(ApprovalService):
    ACTION = "promote-domain-v2"

    def __init__(self, *args, registry: Path, validation_policy: Path,
                 revocations: Path, principal: str,
                 publisher: Path | None = None, publisher_policy_path: Path | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.registry = registry.absolute()
        self.validation_policy = validation_policy.absolute()
        self.publisher = publisher
        self.publisher_policy_path = publisher_policy_path or publisher
        self.revocations = revocations.absolute()
        self.principal = principal.strip()
        if not self.principal:
            raise ApprovalError("APPROVAL_POLICY_UNAVAILABLE", "promotion principal is not configured")
        if not self.registry.is_dir() or any(p.is_symlink() for p in (self.registry, *self.registry.parents)):
            raise ApprovalError("APPROVAL_POLICY_UNAVAILABLE", "unsafe promotion registry")

    def _policy_identity(self) -> str:
        components = ("approval_service.py", "domain_promotion_approval.py", "protected_signer.py")
        return canonical_sha256({
            "registry": str(self.registry), "reviewers": sorted(self.authorized_reviewers), "principal": self.principal,
            "reviewer": self.reviewer_identity, "signer": self.signing_identity,
            "validation_policy": _binding(self.validation_policy, _capture(self.validation_policy, 16384)),
            "executables": {str(p): hashlib.sha256(_capture(p, 1024**2)).hexdigest()
                            for p in (self.signer, self.publisher_policy_path) if p is not None},
            "implementation": {n: hashlib.sha256((Path(__file__).parent / n).read_bytes()).hexdigest()
                               for n in components},
        })

    def request_promotion(self, *, name: str, candidate: Path, validation: Path,
                          replace: bool = False, sign: bool = False,
                          ttl_seconds: int = 900, admission_profile_sha256: str) -> dict:
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", name) or type(replace) is not bool or type(sign) is not bool:
            raise ApprovalError("APPROVAL_POLICY_INVALID", "invalid V2 promotion options")
        candidate, validation = candidate.absolute(), validation.absolute()
        source, evidence = _capture(candidate), _capture(validation)
        destination = self.registry / f"{name}.json"
        prior = _binding(destination, _capture(destination)) if destination.exists() or destination.is_symlink() else None
        if prior and not replace:
            raise ApprovalError("DESTINATION_EXISTS", "replacement requires explicit intent")
        request_id = uuid.uuid4().hex
        staging = self.root / "prepared" / request_id
        staging.mkdir(parents=True, mode=0o700)
        source_path, evidence_path = staging / "candidate.json", staging / "validation.json"
        _write_once(source_path, source); _write_once(evidence_path, evidence)
        policy = read_validation_config(self.validation_policy)
        from .domain_validation_preparation import CapturedDomainCandidate, prepare_captured_domain_candidate
        from .domain_validation_workflow import DOMAIN_VALIDATION_LIMITS
        prepared = prepare_captured_domain_candidate(CapturedDomainCandidate(
            "candidate.input", source, tuple(sorted(DOMAIN_VALIDATION_LIMITS.items()))))
        artifact = staging / "reviewed.json"
        reviewed = promote_validated_candidate(source_path, evidence_path, staging / "preliminary.json",
            accept_candidate_sha256=prepared.candidate_sha256,
            accept_validation_sha256=hashlib.sha256(evidence).hexdigest(), validation_config=policy)
        if reviewed.module_name != name:
            raise ApprovalError("APPROVAL_BINDING_MISMATCH", "candidate module differs from destination")
        reviewed = reviewed.model_copy(update={"approval_operation_id": request_id})
        # The preliminary output is private preparation, never the reviewed registry.
        _write_once(artifact, _canonical_bytes(reviewed.model_dump(mode="json")))
        operation = {"schema": OPERATION_SCHEMA, "name": name,
            "candidate": _binding(candidate, source), "validation": _binding(validation, evidence),
            "captured_candidate": _binding(source_path, source),
            "captured_validation": _binding(evidence_path, evidence),
            "candidate_sha256": reviewed.accepted_candidate_sha256,
            "validation_artifact_sha256": reviewed.accepted_validation_artifact_sha256,
            "context_sha256": reviewed.accepted_applicability_sha256,
            "destination": str(destination), "prior_destination": prior,
            "replace": replace, "sign": sign, "policy_sha256": self._policy_identity(),
            "requester": self.principal,
            "signature_destination": str(staging / "reviewed.sig")}
        manifest = staging / "operation.json"
        _write_once(manifest, _canonical_bytes(operation))
        response = self._create_bound_request(artifact=artifact, evidence_manifest=manifest,
            destination=destination, operation=operation, request_id=request_id,
            admission_profile_sha256=admission_profile_sha256, claim="NO_PROOF",
            verification_status="BOUNDED_VALIDATION_APPLICABLE", ttl_seconds=ttl_seconds)
        response["promotion"] = operation
        return response

    def _validate_request(self, request: dict, request_id: str, *, check_expiry: bool = True):
        super()._validate_request(request, request_id, check_expiry=check_expiry)
        from .mcp_policy import authorize_mcp_invocation
        admission = authorize_mcp_invocation("request_domain_promotion", mode="request", language="model",
            backend="protected-domain-publisher-v1", effects=("workspace_read", "service_state_read", "service_state_write"))
        if not admission.admitted or request["admission_profile_sha256"] != admission.summary()["profile_sha256"] or request.get("verification") != {
                "status": "BOUNDED_VALIDATION_APPLICABLE", "claim": "NO_PROOF", "claim_upgraded_by_signing": False}:
            raise ApprovalError("APPROVAL_BINDING_MISMATCH", "promotion admission or claim boundary changed")
        revoked = _json(self.revocations, "formalspecgen-promotion-revocations-v1")
        if not isinstance(revoked.get("request_ids"), list) or any(
                not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{32}", v) for v in revoked["request_ids"]):
            raise ApprovalError("APPROVAL_POLICY_UNAVAILABLE", "invalid promotion revocations")
        if request_id in revoked["request_ids"]:
            raise ApprovalError("APPROVAL_REVOKED", "promotion approval has been revoked")
        op = request.get("operation")
        keys = {"schema", "name", "candidate", "validation", "captured_candidate", "captured_validation",
                "candidate_sha256", "validation_artifact_sha256", "context_sha256", "destination",
                "prior_destination", "replace", "sign", "policy_sha256", "requester", "signature_destination"}
        if not isinstance(op, dict) or set(op) != keys or op.get("schema") != OPERATION_SCHEMA or \
                not re.fullmatch(r"[a-z_][a-z0-9_]*", str(op.get("name", ""))) or \
                op.get("destination") != str(self.registry / f"{op['name']}.json") or \
                request["destination"] != op["destination"] or \
                type(op.get("sign")) is not bool or type(op.get("replace")) is not bool or \
                op.get("requester") != self.principal or \
                op.get("policy_sha256") != self._policy_identity():
            raise ApprovalError("APPROVAL_BINDING_MISMATCH", "promotion action or operator policy changed")
        staging = self.root / "prepared" / request_id
        for binding, expected in ((request["artifact"], staging / "reviewed.json"),
                                  (request["evidence_manifest"], staging / "operation.json"),
                                  (op["captured_candidate"], staging / "candidate.json"),
                                  (op["captured_validation"], staging / "validation.json")):
            if not isinstance(binding, dict) or binding.get("path") != str(expected):
                raise ApprovalError("APPROVAL_BINDING_MISMATCH", "promotion snapshot destination changed")
        if op["signature_destination"] != str(staging / "reviewed.sig"):
            raise ApprovalError("APPROVAL_BINDING_MISMATCH", "promotion signature destination changed")
        for index, binding in enumerate((op["candidate"], op["validation"], op["captured_candidate"], op["captured_validation"], op["prior_destination"])):
            if binding is None and index == 4:
                continue
            if not isinstance(binding, dict) or set(binding) != {"path", "sha256", "size"} or \
                    not isinstance(binding["path"], str) or not Path(binding["path"]).is_absolute() or \
                    not re.fullmatch(r"[0-9a-f]{64}", str(binding["sha256"])) or \
                    type(binding["size"]) is not int or not 0 <= binding["size"] <= 8 * 1024**2:
                raise ApprovalError("APPROVAL_BINDING_MISMATCH", "invalid promotion input binding")
        if _json(Path(request["evidence_manifest"]["path"]), OPERATION_SCHEMA) != op:
            raise ApprovalError("APPROVAL_BINDING_MISMATCH", "promotion descriptor changed")

    @staticmethod
    def _public_request(request: dict, request_sha256: str, status: str) -> dict:
        result = ApprovalService._public_request(request, request_sha256, status)
        result["promotion"] = request["operation"]
        return result

    def _authenticate_decision(self, root: Path, request: dict):
        # Shared verifier handles principal, request hash and signature. The strict
        # parser additionally rejects ambiguous or oversized control documents.
        if (root / "decision.json").exists():
            _json(root / "decision.json")
        _capture(root / "decision.json.sig", 1024**2) if (root / "decision.json.sig").exists() else None
        return super()._authenticate_decision(root, request)

    def _authorization(self, root: Path, *, check_expiry: bool = True):
        """Verify captured control bytes; pathname mutation cannot change authority."""
        with tempfile.TemporaryDirectory(prefix="promotion-authority-") as directory:
            snapshot = Path(directory)
            raw = _capture(root / "request.json", 1024**2)
            request = _object(raw, APPROVAL_REQUEST_SCHEMA)
            self._validate_request(request, root.name, check_expiry=check_expiry)
            (snapshot / "request.json").write_bytes(raw)
            for name in ("decision.json", "decision.json.sig"):
                if not (root / name).exists():
                    raise ApprovalError("APPROVAL_REQUIRED", "an authenticated human decision is absent")
                (snapshot / name).write_bytes(_capture(root / name, 1024**2))
            decision, reviewer, request_sha = self._authenticate_decision(snapshot, request)
            return request, decision, reviewer, request_sha

    def execute(self, request_id: str, **_kwargs) -> dict:
        """MCP delegates the action to a separately configured operator helper."""
        root = self._request_root(request_id)
        self._authorization(root, check_expiry=not (root / "receipt.json").exists())
        if self.publisher is None or self.publisher.is_symlink() or not os.access(self.publisher, os.X_OK):
            raise ApprovalError("PROTECTED_PUBLISHER_UNAVAILABLE", "protected promotion publisher is unavailable")
        result = self.runner([str(self.publisher), "--request-id", request_id],
                             capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise ApprovalError("PROTECTED_PUBLICATION_FAILED", "operator publisher rejected the action")
        return self._validated_receipt_response(root, root / "receipt.json")

    def _validated_receipt_response(self, root: Path, receipt_path: Path) -> dict:
        request, decision, reviewer, request_sha = self._authorization(root, check_expiry=False)
        receipt = _json(receipt_path, APPROVAL_RECEIPT_SCHEMA)
        if receipt.get("signature") is not None and not isinstance(receipt["signature"], dict):
            raise ApprovalError("APPROVAL_STATE_INVALID", "invalid promotion signature binding")
        for key, value in {"request_id": root.name, "request_sha256": request_sha,
                           "operation_id": request["operation_id"], "policy_version": request["policy_version"],
                           "admission_profile_sha256": request["admission_profile_sha256"],
                           "decision": decision["decision"], "reviewer_signing_fingerprint": reviewer["signing_fingerprint"],
                           "action": self.ACTION, "operation": request["operation"],
                           "artifact": request["artifact"], "evidence_manifest": request["evidence_manifest"],
                           "verification": request["verification"], "claim_upgraded_by_signing": False,
                           "reviewer_identity": reviewer["primary_fingerprint"]}.items():
            if receipt.get(key) != value:
                raise ApprovalError("APPROVAL_STATE_INVALID", "promotion receipt binding changed")
        if receipt.get("status") == "PROMOTED" and decision["decision"] == "approve":
            expected_publication = {**request["artifact"], "path": request["destination"]}
            if receipt.get("publication") != expected_publication or (
                    receipt.get("signature") is not None and receipt["signature"].get("path") != request["operation"]["signature_destination"]):
                raise ApprovalError("APPROVAL_STATE_INVALID", "publication differs from approved bytes or destination")
            _check(receipt["publication"])
            if receipt.get("signature") is not None:
                _check(receipt["signature"])
                _verify_detached_signature(Path(receipt["publication"]["path"]),
                    Path(receipt["signature"]["path"]), gpg_home=self.verifier_home,
                    authorized_keys={self.signing_identity}, expected_identity=self.signing_identity, runner=self.runner)
            if bool(receipt.get("signature")) != request["operation"]["sign"]:
                raise ApprovalError("APPROVAL_STATE_INVALID", "promotion signing outcome changed")
        elif receipt.get("status") != "DENIED" or decision["decision"] != "deny":
            raise ApprovalError("APPROVAL_STATE_INVALID", "invalid promotion outcome")
        result = self._receipt_response(receipt, receipt_path)
        result.update(request_satisfied=receipt["status"] == "PROMOTED", publication=receipt.get("publication"), promotion=request["operation"])
        return result

    def status(self, request_id: str) -> dict:
        """Inspect durable phases without publishing or signing anything."""
        result = super().status(request_id)
        root = self._request_root(request_id)
        request = _json(root / "request.json", APPROVAL_REQUEST_SCHEMA)
        op = request["operation"]
        published = False
        intent = root / "publication-intent.json"
        if intent.exists():
            expected = {"request_sha256": hashlib.sha256(_capture(root / "request.json")).hexdigest(),
                        "artifact": request["artifact"], "destination": request["destination"]}
            if _json(intent) != expected:
                raise ApprovalError("APPROVAL_STATE_INVALID", "publication recovery intent changed")
            destination = Path(request["destination"])
            published = destination.exists() and _capture(destination) == _check(request["artifact"])
        signed = False
        signature = Path(op["signature_destination"])
        if signature.exists():
            _verify_detached_signature(Path(request["artifact"]["path"]), signature,
                gpg_home=self.verifier_home, authorized_keys={self.signing_identity},
                expected_identity=self.signing_identity, runner=self.runner)
            signed = True
        result["phases"] = {
            "approval": result["status"],
            "publication": "PUBLISHED" if published else "NOT_PUBLISHED",
            "signing": "SIGNED" if signed else ("PENDING" if op["sign"] else "NOT_REQUESTED"),
            "receipt": "COMMITTED" if (root / "receipt.json").exists() else "NOT_COMMITTED",
        }
        return result

    def publish_approved(self, request_id: str, *, before_receipt=None) -> dict:
        """Operator-side execution. Never exposed as an MCP callable."""
        root = self._request_root(request_id)
        with (self.registry / ".promotion.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if (root / "receipt.json").exists():
                return self._validated_receipt_response(root, root / "receipt.json")
            request, decision, reviewer, request_sha = self._authorization(root)
            op = request["operation"]
            if decision["decision"] == "deny":
                receipt = self._receipt(request, request_sha, decision, reviewer, status="DENIED", signature=None)
                receipt["operation"] = op
                _write_once(root / "receipt.json", _canonical_bytes(receipt))
                return self._validated_receipt_response(root, root / "receipt.json")
            # Verify live inputs, then work exclusively on captured bytes.
            source, validation = _check(op["candidate"]), _check(op["validation"])
            if source != _check(op["captured_candidate"]) or validation != _check(op["captured_validation"]):
                raise ApprovalError("APPROVED_ARTIFACT_CHANGED", "captured promotion inputs differ")
            artifact = _check(request["artifact"])
            _check(request["evidence_manifest"])
            with tempfile.TemporaryDirectory(prefix="promotion-recheck-") as temp:
                temp = Path(temp); (temp / "candidate.json").write_bytes(source); (temp / "validation.json").write_bytes(validation)
                reviewed = promote_validated_candidate(temp / "candidate.json", temp / "validation.json", temp / "reviewed.json",
                    accept_candidate_sha256=op["candidate_sha256"], accept_validation_sha256=op["validation_artifact_sha256"],
                    validation_config=read_validation_config(self.validation_policy))
                reviewed = reviewed.model_copy(update={"approval_operation_id": request_id})
                if _canonical_bytes(reviewed.model_dump(mode="json")) != artifact or reviewed.accepted_applicability_sha256 != op["context_sha256"]:
                    raise ApprovalError("APPROVAL_BINDING_MISMATCH", "reviewed artifact or applicability changed")
            destination = Path(request["destination"])
            intent = root / "publication-intent.json"
            recovered = intent.exists() and destination.exists() and _capture(destination) == artifact
            if intent.exists() and _json(intent) != {"request_sha256": request_sha, "artifact": request["artifact"], "destination": str(destination)}:
                raise ApprovalError("APPROVAL_STATE_INVALID", "publication recovery intent changed")
            if not recovered:
                observed = _binding(destination, _capture(destination)) if destination.exists() or destination.is_symlink() else None
                if observed != op["prior_destination"] or (observed is not None and not op["replace"]):
                    raise ApprovalError("DESTINATION_CHANGED", "reviewed destination changed after approval")
                if not intent.exists():
                    _write_once(intent, _canonical_bytes({"request_sha256": request_sha, "artifact": request["artifact"], "destination": str(destination)}))
            signature_binding = None
            if op["sign"]:
                signature = Path(op["signature_destination"])
                if not signature.exists():
                    self._invoke_signer(root / "request.json", root / "decision.json", root / "decision.json.sig",
                                        Path(request["artifact"]["path"]), signature)
                _verify_detached_signature(Path(request["artifact"]["path"]), signature, gpg_home=self.verifier_home,
                    authorized_keys={self.signing_identity}, expected_identity=self.signing_identity, runner=self.runner)
                signature_binding = _binding(signature, _capture(signature, 1024**2))
            if not recovered:
                # Signing can take time. Recheck the approved destination under
                # the publisher lock immediately before replacing it.
                observed = _binding(destination, _capture(destination)) if destination.exists() or destination.is_symlink() else None
                if observed != op["prior_destination"]:
                    raise ApprovalError("DESTINATION_CHANGED", "reviewed destination changed during signing")
                # Unique operation ID in the bytes makes post-rename recovery unambiguous.
                descriptor, temporary = tempfile.mkstemp(prefix=".promotion-", dir=self.registry)
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(artifact); handle.flush(); os.fsync(handle.fileno())
                    os.replace(temporary, destination); _fsync_directory(self.registry)
                finally:
                    Path(temporary).unlink(missing_ok=True)
            publication = _binding(destination, artifact)
            receipt = self._receipt(request, request_sha, decision, reviewer, status="PROMOTED", signature=signature_binding)
            receipt.update(operation=op, publication=publication)
            if before_receipt: before_receipt()
            _write_once(root / "receipt.json", _canonical_bytes(receipt))
            return self._validated_receipt_response(root, root / "receipt.json")


def configured_service(*, publisher: bool) -> DomainPromotionApprovalService:
    """Resolve authority exclusively from operator-controlled configuration."""
    from .operator_configuration import operator_controlled_path
    from .trust import list_trusted_keys
    path = operator_controlled_path
    registry = path("FORMALSPECGEN_PROMOTION_REGISTRY")
    policy = path("FORMALSPECGEN_PROMOTION_VALIDATION_POLICY", require_file=True)
    trust = path("FORMALSPECGEN_APPROVAL_TRUST_REGISTRY", require_file=True)
    return DomainPromotionApprovalService(path("FORMALSPECGEN_APPROVAL_ROOT"),
        verifier_home=path("FORMALSPECGEN_APPROVAL_GNUPGHOME"),
        authorized_reviewers={item["key_id"] for item in list_trusted_keys(trust)},
        signer=path("FORMALSPECGEN_APPROVAL_SIGNER", require_file=True),
        signing_identity=os.environ.get("FORMALSPECGEN_SIGNING_IDENTITY", ""),
        reviewer_identity=os.environ.get("FORMALSPECGEN_REVIEWER_IDENTITY", ""),
        registry=registry, validation_policy=policy,
        revocations=path("FORMALSPECGEN_PROMOTION_REVOCATIONS", require_file=True),
        principal=os.environ.get("FORMALSPECGEN_PROMOTION_PRINCIPAL", ""),
        publisher_policy_path=path("FORMALSPECGEN_PROMOTION_PUBLISHER", require_file=True),
        publisher=path("FORMALSPECGEN_PROMOTION_PUBLISHER", require_file=True) if publisher else None)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Publish an authenticated V2 promotion")
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = configured_service(publisher=False).publish_approved(args.request_id)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": getattr(exc, "code", "PROMOTION_FAILED"), "claim": "NO_PROOF", "message": str(exc)}))
        return 2
    print(json.dumps(result)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
