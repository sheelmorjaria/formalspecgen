# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Artifact-bound human approval and protected-action coordination.

The MCP process may create, inspect, and execute an already-authorized request.
It cannot create the human decision: that decision is a detached signature made
outside MCP and verified against an operator-controlled reviewer policy.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


APPROVAL_POLICY_VERSION = "formalspecgen-approval-policy-v1"
APPROVAL_REQUEST_SCHEMA = "formalspecgen-approval-request-v1"
APPROVAL_DECISION_SCHEMA = "formalspecgen-approval-decision-v1"
APPROVAL_RECEIPT_SCHEMA = "formalspecgen-approval-receipt-v1"
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")


class ApprovalError(ValueError):
    """A protected action cannot safely advance."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.code, "claim": "NO_PROOF",
            "request_satisfied": False, "message": str(self),
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ApprovalError("ARTIFACT_UNAVAILABLE", f"unsafe artifact: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ApprovalError(
            "APPROVAL_REPLAY", f"approval state already exists: {path.name}") from exc
    _fsync_directory(path.parent)


def _load_json(path: Path, schema: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApprovalError(
            "APPROVAL_STATE_INVALID", f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ApprovalError(
            "APPROVAL_STATE_INVALID", f"invalid {path.name} schema")
    return value


def _matches_identity(observed: str, expected: str) -> bool:
    left, right = observed.upper(), expected.upper()
    return left == right or left.endswith(right) or right.endswith(left)


def _verify_detached_signature(
        artifact: Path, signature: Path, *, gpg_home: Path,
        authorized_keys: set[str], expected_identity: str | None,
        runner: Callable[..., Any] = subprocess.run) -> str:
    command = [
        "gpg", "--homedir", str(gpg_home), "--batch", "--status-fd", "1",
        "--verify", str(signature), str(artifact),
    ]
    result = runner(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise ApprovalError(
            "APPROVAL_SIGNATURE_INVALID",
            f"detached signature verification failed for {artifact.name}")
    valid = next((
        line.split()[2] for line in (result.stdout or "").splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) > 2
    ), "")
    if not valid:
        raise ApprovalError(
            "APPROVAL_SIGNATURE_INVALID", "GPG did not report a valid signer")
    if not any(_matches_identity(valid, key) for key in authorized_keys):
        raise ApprovalError(
            "APPROVAL_REVIEWER_UNAUTHORIZED", "decision signer is not trusted")
    if expected_identity and not _matches_identity(valid, expected_identity):
        raise ApprovalError(
            "APPROVAL_REVIEWER_MISMATCH",
            "decision signer does not match the request-bound reviewer")
    return valid


class ApprovalService:
    """Durable approval coordinator with an external protected signer."""

    def __init__(
            self, root: Path, *, verifier_home: Path,
            authorized_reviewers: Iterable[str], signer: Path | None,
            signing_identity: str, reviewer_identity: str,
            runner: Callable[..., Any] = subprocess.run,
            now: Callable[[], datetime] = _utc_now):
        self.root = root.resolve()
        self.verifier_home = verifier_home.resolve()
        self.authorized_reviewers = {
            str(value).strip().upper() for value in authorized_reviewers
            if str(value).strip()
        }
        self.signer = signer.resolve() if signer is not None else None
        self.signing_identity = signing_identity.strip()
        self.reviewer_identity = reviewer_identity.strip()
        self.runner = runner
        self.now = now
        if not self.authorized_reviewers:
            raise ApprovalError(
                "APPROVAL_POLICY_UNAVAILABLE", "no authorized reviewers configured")
        if not self.signing_identity or not self.reviewer_identity:
            raise ApprovalError(
                "APPROVAL_POLICY_UNAVAILABLE",
                "signing and reviewer identities must be configured")
        if not any(_matches_identity(
                self.reviewer_identity, key) for key in self.authorized_reviewers):
            raise ApprovalError(
                "APPROVAL_POLICY_UNAVAILABLE",
                "configured reviewer identity is not in the trusted registry")
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ApprovalError("APPROVAL_POLICY_UNAVAILABLE", "unsafe approval root")

    def create_request(
            self, *, artifact: Path, evidence_manifest: Path,
            admission_profile_sha256: str, claim: str,
            verification_status: str, ttl_seconds: int = 900) -> dict[str, Any]:
        if ttl_seconds < 1 or ttl_seconds > 86400:
            raise ApprovalError(
                "APPROVAL_POLICY_INVALID", "approval expiry must be 1..86400 seconds")
        artifact = artifact.resolve()
        evidence_manifest = evidence_manifest.resolve()
        artifact_sha256, artifact_size = _sha256_file(artifact)
        evidence_sha256, evidence_size = _sha256_file(evidence_manifest)
        if not re.fullmatch(r"[0-9a-f]{64}", admission_profile_sha256):
            raise ApprovalError(
                "APPROVAL_POLICY_INVALID", "admission profile digest is invalid")
        request_id = uuid.uuid4().hex
        request_root = self.root / request_id
        request_root.mkdir(mode=0o700)
        created = self.now()
        request = {
            "schema": APPROVAL_REQUEST_SCHEMA,
            "policy_version": APPROVAL_POLICY_VERSION,
            "request_id": request_id,
            "operation_id": request_id,
            "nonce": secrets.token_hex(32),
            "action": "sign-refactor-evidence",
            "artifact": {
                "path": str(artifact), "sha256": artifact_sha256,
                "size": artifact_size,
            },
            "evidence_manifest": {
                "path": str(evidence_manifest), "sha256": evidence_sha256,
                "size": evidence_size,
            },
            "destination": str(request_root / "artifact.sig"),
            "signing_identity": self.signing_identity,
            "reviewer_identity": self.reviewer_identity,
            "admission_profile_sha256": admission_profile_sha256,
            "verification": {
                "status": verification_status, "claim": claim,
                "claim_upgraded_by_signing": False,
            },
            "created_at": _iso(created),
            "expires_at": _iso(created + timedelta(seconds=ttl_seconds)),
        }
        encoded = _canonical_bytes(request)
        _write_once(request_root / "request.json", encoded)
        return self._public_request(request, _sha256_bytes(encoded), "PENDING")

    def status(self, request_id: str) -> dict[str, Any]:
        root = self._request_root(request_id)
        request_path = root / "request.json"
        request = _load_json(request_path, APPROVAL_REQUEST_SCHEMA)
        request_sha256 = _sha256_file(request_path)[0]
        receipt_path = root / "receipt.json"
        if receipt_path.is_file():
            return self._validated_receipt_response(root, receipt_path)
        self._validate_request(request, request_id)
        state = "DECISION_RECORDED" if (root / "decision.json").is_file() else "PENDING"
        return self._public_request(request, request_sha256, state)

    def execute(
            self, request_id: str, *,
            before_receipt: Callable[[], None] | None = None) -> dict[str, Any]:
        root = self._request_root(request_id)
        lock_path = root / "execution.lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            receipt_path = root / "receipt.json"
            if receipt_path.is_file():
                return self._validated_receipt_response(root, receipt_path)
            request_path = root / "request.json"
            decision_path = root / "decision.json"
            decision_signature = root / "decision.json.sig"
            request = _load_json(request_path, APPROVAL_REQUEST_SCHEMA)
            self._validate_request(request, request_id)
            if not decision_path.is_file() or not decision_signature.is_file():
                raise ApprovalError(
                    "APPROVAL_REQUIRED", "an authenticated human decision is absent")
            decision = _load_json(decision_path, APPROVAL_DECISION_SCHEMA)
            request_sha256 = _sha256_file(request_path)[0]
            self._validate_decision(decision, request, request_sha256)
            reviewer = _verify_detached_signature(
                decision_path, decision_signature,
                gpg_home=self.verifier_home,
                authorized_keys=self.authorized_reviewers,
                expected_identity=request["reviewer_identity"], runner=self.runner)
            if decision["decision"] == "deny":
                receipt = self._receipt(
                    request, request_sha256, decision, reviewer,
                    status="DENIED", signature=None)
                _write_once(receipt_path, _canonical_bytes(receipt))
                return self._receipt_response(receipt, receipt_path)

            artifact = Path(request["artifact"]["path"])
            evidence = Path(request["evidence_manifest"]["path"])
            self._validate_bound_file(artifact, request["artifact"], "artifact")
            self._validate_bound_file(
                evidence, request["evidence_manifest"], "evidence manifest")
            signature = Path(request["destination"])
            if not signature.is_file():
                self._invoke_signer(
                    request_path, decision_path, decision_signature,
                    artifact, signature)
            signer = _verify_detached_signature(
                artifact, signature, gpg_home=self.verifier_home,
                authorized_keys={request["signing_identity"]},
                expected_identity=request["signing_identity"], runner=self.runner)
            signature_sha256, signature_size = _sha256_file(signature)
            receipt = self._receipt(
                request, request_sha256, decision, reviewer,
                status="SIGNED", signature={
                    "path": str(signature), "sha256": signature_sha256,
                    "size": signature_size, "signer_identity": signer,
                })
            if before_receipt is not None:
                before_receipt()
            _write_once(receipt_path, _canonical_bytes(receipt))
            return self._receipt_response(receipt, receipt_path)

    def _invoke_signer(
            self, request: Path, decision: Path, approval_signature: Path,
            artifact: Path, output: Path) -> None:
        if self.signer is None or self.signer.is_symlink() or \
                not self.signer.is_file() or not os.access(self.signer, os.X_OK):
            raise ApprovalError(
                "PROTECTED_SIGNER_UNAVAILABLE", "protected signer is unavailable")
        command = [
            str(self.signer), "--request", str(request),
            "--decision", str(decision),
            "--approval-signature", str(approval_signature),
            "--artifact", str(artifact), "--output", str(output),
        ]
        result = self.runner(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise ApprovalError(
                "PROTECTED_SIGNING_FAILED",
                "protected signer rejected or failed the approved action")
        if not output.is_file():
            raise ApprovalError(
                "PROTECTED_SIGNING_FAILED", "protected signer emitted no signature")

    def _validate_request(
            self, request: dict[str, Any], request_id: str, *,
            check_expiry: bool = True) -> None:
        artifact = request.get("artifact")
        evidence = request.get("evidence_manifest")
        if request.get("request_id") != request_id or \
                request.get("operation_id") != request_id or \
                not _REQUEST_ID.fullmatch(request_id) or \
                request.get("policy_version") != APPROVAL_POLICY_VERSION or \
                request.get("action") != "sign-refactor-evidence" or \
                not isinstance(artifact, dict) or \
                not isinstance(evidence, dict) or \
                any(not isinstance(binding.get("path"), str) or
                    not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("sha256", ""))) or
                    not isinstance(binding.get("size"), int) or binding["size"] < 0
                    for binding in (artifact, evidence)) or \
                not isinstance(request.get("destination"), str) or \
                not request.get("signing_identity") or \
                not request.get("reviewer_identity") or \
                not re.fullmatch(
                    r"[0-9a-f]{64}", str(request.get("admission_profile_sha256", ""))):
            raise ApprovalError("APPROVAL_STATE_INVALID", "approval request binding changed")
        try:
            expires = datetime.fromisoformat(str(request["expires_at"]))
        except (KeyError, ValueError) as exc:
            raise ApprovalError(
                "APPROVAL_STATE_INVALID", "approval expiry is invalid") from exc
        if expires.tzinfo is None:
            raise ApprovalError("APPROVAL_STATE_INVALID", "approval expiry lacks timezone")
        if check_expiry and self.now() >= expires:
            raise ApprovalError("APPROVAL_EXPIRED", "approval request has expired")

    def _validated_receipt_response(
            self, root: Path, receipt_path: Path) -> dict[str, Any]:
        receipt = _load_json(receipt_path, APPROVAL_RECEIPT_SCHEMA)
        request_path = root / "request.json"
        request = _load_json(request_path, APPROVAL_REQUEST_SCHEMA)
        self._validate_request(
            request, root.name, check_expiry=False)
        request_sha256 = _sha256_file(request_path)[0]
        if receipt.get("request_id") != request.get("request_id") or \
                receipt.get("operation_id") != request.get("operation_id") or \
                receipt.get("request_sha256") != request_sha256 or \
                receipt.get("action") != request.get("action") or \
                receipt.get("policy_version") != APPROVAL_POLICY_VERSION or \
                receipt.get("artifact") != request.get("artifact") or \
                receipt.get("evidence_manifest") != request.get("evidence_manifest") or \
                receipt.get("admission_profile_sha256") != request.get(
                    "admission_profile_sha256") or \
                receipt.get("verification") != request.get("verification") or \
                receipt.get("claim_upgraded_by_signing") is not False or \
                not _matches_identity(
                    str(receipt.get("reviewer_identity", "")),
                    str(request.get("reviewer_identity", ""))):
            raise ApprovalError(
                "APPROVAL_STATE_INVALID", "approval receipt binding changed")
        self._validate_bound_file(
            Path(request["artifact"]["path"]), request["artifact"], "artifact")
        self._validate_bound_file(
            Path(request["evidence_manifest"]["path"]),
            request["evidence_manifest"], "evidence manifest")
        if receipt.get("status") == "SIGNED":
            signature = receipt.get("signature")
            if not isinstance(signature, dict):
                raise ApprovalError(
                    "APPROVAL_STATE_INVALID", "signed receipt lacks signature binding")
            signature_path = Path(str(signature.get("path", "")))
            self._validate_bound_file(signature_path, signature, "signature")
            _verify_detached_signature(
                Path(request["artifact"]["path"]), signature_path,
                gpg_home=self.verifier_home,
                authorized_keys={request["signing_identity"]},
                expected_identity=request["signing_identity"], runner=self.runner)
        elif receipt.get("status") != "DENIED":
            raise ApprovalError(
                "APPROVAL_STATE_INVALID", "unknown approval receipt outcome")
        return self._receipt_response(receipt, receipt_path)

    @staticmethod
    def _validate_decision(
            decision: dict[str, Any], request: dict[str, Any],
            request_sha256: str) -> None:
        required = {
            "request_id": request["request_id"],
            "operation_id": request["operation_id"],
            "request_sha256": request_sha256,
            "action": request["action"],
            "artifact_sha256": request["artifact"]["sha256"],
            "evidence_manifest_sha256": request["evidence_manifest"]["sha256"],
            "destination": request["destination"],
            "signing_identity": request["signing_identity"],
            "policy_version": request["policy_version"],
        }
        if decision.get("decision") not in {"approve", "deny"} or any(
                decision.get(key) != value for key, value in required.items()):
            raise ApprovalError(
                "APPROVAL_BINDING_MISMATCH", "human decision does not bind this action")

    @staticmethod
    def _validate_bound_file(
            path: Path, binding: dict[str, Any], label: str) -> None:
        digest, size = _sha256_file(path)
        if digest != binding.get("sha256") or size != binding.get("size"):
            raise ApprovalError(
                "APPROVED_ARTIFACT_CHANGED", f"{label} changed after approval request")

    def _request_root(self, request_id: str) -> Path:
        if not _REQUEST_ID.fullmatch(request_id):
            raise ApprovalError("APPROVAL_NOT_FOUND", "invalid approval request id")
        root = self.root / request_id
        if root.is_symlink() or not root.is_dir():
            raise ApprovalError("APPROVAL_NOT_FOUND", "approval request does not exist")
        return root

    @staticmethod
    def _public_request(
            request: dict[str, Any], request_sha256: str,
            status: str) -> dict[str, Any]:
        return {
            "status": status, "claim": request["verification"]["claim"],
            "request_satisfied": False,
            "approval": {
                "status": status, "request_id": request["request_id"],
                "operation_id": request["operation_id"],
                "action": request["action"],
                "request_sha256": request_sha256,
                "artifact": dict(request["artifact"]),
                "evidence_manifest": dict(request["evidence_manifest"]),
                "destination": request["destination"],
                "signing_identity": request["signing_identity"],
                "reviewer_identity": request["reviewer_identity"],
                "policy_version": request["policy_version"],
                "expires_at": request["expires_at"],
                "private_key_exposed": False,
            },
            "verification": dict(request["verification"]),
        }

    def _receipt(
            self, request: dict[str, Any], request_sha256: str,
            decision: dict[str, Any], reviewer: str, *, status: str,
            signature: dict[str, Any] | None) -> dict[str, Any]:
        return {
            "schema": APPROVAL_RECEIPT_SCHEMA,
            "policy_version": APPROVAL_POLICY_VERSION,
            "request_id": request["request_id"],
            "operation_id": request["operation_id"],
            "request_sha256": request_sha256,
            "action": request["action"],
            "status": status,
            "decision": decision["decision"],
            "reviewer_identity": reviewer,
            "artifact": dict(request["artifact"]),
            "evidence_manifest": dict(request["evidence_manifest"]),
            "admission_profile_sha256": request["admission_profile_sha256"],
            "signature": signature,
            "verification": dict(request["verification"]),
            "completed_at": _iso(self.now()),
            "claim_upgraded_by_signing": False,
        }

    @staticmethod
    def _receipt_response(
            receipt: dict[str, Any], receipt_path: Path) -> dict[str, Any]:
        digest, size = _sha256_file(receipt_path)
        signed = receipt["status"] == "SIGNED"
        return {
            "status": receipt["status"],
            "claim": receipt["verification"]["claim"],
            "request_satisfied": signed,
            "approval": {
                "status": receipt["status"],
                "request_id": receipt["request_id"],
                "operation_id": receipt["operation_id"],
                "action": receipt["action"],
                "reviewer_identity": receipt["reviewer_identity"],
                "private_key_exposed": False,
            },
            "verification": dict(receipt["verification"]),
            "signature": receipt.get("signature"),
            "approval_receipt": {
                "path": str(receipt_path), "sha256": digest, "size": size,
                "schema": APPROVAL_RECEIPT_SCHEMA,
            },
        }


def record_human_decision(
        root: Path, request_id: str, *, decision: str, signing_key: str,
        gpg_home: Path | None = None,
        runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Record a human decision outside MCP using the reviewer's own GPG key."""
    if decision not in {"approve", "deny"}:
        raise ApprovalError("APPROVAL_DECISION_INVALID", "decision must be approve or deny")
    if not _REQUEST_ID.fullmatch(request_id):
        raise ApprovalError("APPROVAL_NOT_FOUND", "invalid approval request id")
    request_root = root.resolve() / request_id
    request_path = request_root / "request.json"
    request = _load_json(request_path, APPROVAL_REQUEST_SCHEMA)
    request_sha256 = _sha256_file(request_path)[0]
    value = {
        "schema": APPROVAL_DECISION_SCHEMA,
        "policy_version": request["policy_version"],
        "request_id": request["request_id"],
        "operation_id": request["operation_id"],
        "request_sha256": request_sha256,
        "action": request["action"],
        "artifact_sha256": request["artifact"]["sha256"],
        "evidence_manifest_sha256": request["evidence_manifest"]["sha256"],
        "destination": request["destination"],
        "signing_identity": request["signing_identity"],
        "decision": decision,
        "decided_at": _iso(_utc_now()),
    }
    decision_path = request_root / "decision.json"
    signature_path = request_root / "decision.json.sig"
    _write_once(decision_path, _canonical_bytes(value))
    command = ["gpg"]
    if gpg_home is not None:
        command.extend(("--homedir", str(gpg_home.resolve())))
    command.extend((
        "--batch", "--yes", "--local-user", signing_key,
        "--detach-sign", "--output", str(signature_path), str(decision_path)))
    try:
        result = runner(command, capture_output=True, text=True)
        if result.returncode != 0 or not signature_path.is_file():
            raise ApprovalError(
                "APPROVAL_SIGNATURE_FAILED", "human decision signature failed")
    except Exception:
        signature_path.unlink(missing_ok=True)
        decision_path.unlink(missing_ok=True)
        raise
    return {
        "status": "DECISION_RECORDED", "request_id": request_id,
        "decision": decision, "request_sha256": request_sha256,
        "decision_sha256": _sha256_file(decision_path)[0],
        "signature_sha256": _sha256_file(signature_path)[0],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Record an authenticated human decision outside MCP")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--decision", required=True, choices=("approve", "deny"))
    parser.add_argument("--key", required=True)
    parser.add_argument("--gpg-home", type=Path)
    args = parser.parse_args(argv)
    result = record_human_decision(
        args.root, args.request_id, decision=args.decision,
        signing_key=args.key, gpg_home=args.gpg_home)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
