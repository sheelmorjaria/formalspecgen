# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Operator-side signer for an exact, authenticated approval request.

This process is deliberately configured independently of MCP.  It receives an
immutable request and signed human decision, revalidates every binding, and
creates one detached signature without replacing an existing output.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .approval_service import (
    APPROVAL_DECISION_SCHEMA,
    APPROVAL_POLICY_VERSION,
    APPROVAL_REQUEST_SCHEMA,
    ApprovalError,
    _fsync_directory,
    _load_json,
    _sha256_file,
    _verify_detached_signature,
)


_CONTROL_INPUT_LIMIT = 1024 * 1024
_SIGNED_INPUT_LIMIT = 8 * 1024 * 1024
_FULL_FINGERPRINT = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")


def _capture_file(
        source: Path, destination: Path, *, max_bytes: int,
        label: str) -> tuple[str, int]:
    """Capture one regular file once into signer-private storage.

    The returned digest and every later parser/cryptographic operation concern
    the captured bytes.  Mutating or replacing the original pathname after
    this point therefore cannot change what GPG signs.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ApprovalError(
            "ARTIFACT_UNAVAILABLE", f"cannot capture {label}") from exc
    content = bytearray()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ApprovalError("ARTIFACT_UNAVAILABLE", f"unsafe {label}")
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > max_bytes:
                raise ApprovalError(
                    "SIGNER_INPUT_LIMIT_EXCEEDED", f"{label} exceeds signer limit")
    finally:
        os.close(descriptor)
    with destination.open("xb") as handle:
        os.chmod(destination, 0o600)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return _sha256_file(destination)


def _binding_limit(binding: object, label: str) -> int:
    if not isinstance(binding, dict) or not isinstance(binding.get("size"), int):
        raise ApprovalError("APPROVAL_BINDING_MISMATCH", f"invalid {label} binding")
    size = int(binding["size"])
    if size < 0 or size > _SIGNED_INPUT_LIMIT:
        raise ApprovalError(
            "SIGNER_INPUT_LIMIT_EXCEEDED", f"{label} exceeds signer limit")
    return size


def _required_path(variable: str, *, directory: bool = False) -> Path:
    raw = os.environ.get(variable)
    if not raw:
        raise ApprovalError("SIGNER_POLICY_UNAVAILABLE", f"{variable} is not configured")
    path = Path(raw).expanduser().resolve()
    valid = path.is_dir() if directory else path.is_file()
    if path.is_symlink() or not valid:
        raise ApprovalError("SIGNER_POLICY_UNAVAILABLE", f"unsafe {variable}")
    return path


def _authorized_reviewers() -> set[str]:
    path = _required_path("FORMALSPECGEN_APPROVAL_TRUST_REGISTRY")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        keys = {
            str(item["key_id"]).strip().upper()
            for item in value.get("keys", ()) if item.get("key_id")
        }
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ApprovalError(
            "SIGNER_POLICY_UNAVAILABLE", "invalid reviewer trust registry") from exc
    if not keys:
        raise ApprovalError("SIGNER_POLICY_UNAVAILABLE", "no trusted reviewers configured")
    if any(not _FULL_FINGERPRINT.fullmatch(key) for key in keys):
        raise ApprovalError(
            "SIGNER_POLICY_UNAVAILABLE",
            "reviewer identities must be complete OpenPGP fingerprints")
    return keys


def sign_approved_artifact(
        *, request_path: Path, decision_path: Path,
        approval_signature: Path, artifact: Path, output: Path,
        runner=subprocess.run) -> dict[str, object]:
    """Revalidate and execute exactly one approved signing action."""
    artifact = artifact.resolve()
    output = output.resolve()
    with tempfile.TemporaryDirectory(prefix="formalspecgen-signer-") as directory:
        snapshot_root = Path(directory)
        snapshot_root.chmod(0o700)
        request_snapshot = snapshot_root / "request.json"
        decision_snapshot = snapshot_root / "decision.json"
        approval_snapshot = snapshot_root / "decision.json.sig"
        artifact_snapshot = snapshot_root / "artifact.bin"
        evidence_snapshot = snapshot_root / "evidence-manifest.bin"
        _capture_file(
            request_path, request_snapshot, max_bytes=_CONTROL_INPUT_LIMIT,
            label="approval request")
        request = _load_json(request_snapshot, APPROVAL_REQUEST_SCHEMA)
        request_sha256, _ = _sha256_file(request_snapshot)
        artifact_binding = request.get("artifact")
        evidence_binding = request.get("evidence_manifest")
        try:
            expires = datetime.fromisoformat(str(request["expires_at"]))
        except (KeyError, ValueError) as exc:
            raise ApprovalError(
                "APPROVAL_BINDING_MISMATCH", "approval expiry is invalid") from exc
        if expires.tzinfo is None or datetime.now(timezone.utc) >= expires:
            raise ApprovalError("APPROVAL_EXPIRED", "approval request has expired")
        if request.get("policy_version") != APPROVAL_POLICY_VERSION or \
                request.get("action") != "sign-refactor-evidence" or \
                request.get("request_id") != request.get("operation_id") or \
                not request.get("reviewer_identity") or \
                not request.get("signing_identity") or \
                not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(request.get("admission_profile_sha256", ""))) or \
                not isinstance(artifact_binding, dict) or \
                not isinstance(evidence_binding, dict) or \
                any(not isinstance(binding.get("path"), str) or
                    not re.fullmatch(
                        r"[0-9a-f]{64}", str(binding.get("sha256", ""))) or
                    not isinstance(binding.get("size"), int)
                    for binding in (artifact_binding, evidence_binding)):
            raise ApprovalError(
                "APPROVAL_BINDING_MISMATCH", "unsupported approval action")
        if str(artifact) != artifact_binding.get("path") or \
                str(output) != request.get("destination"):
            raise ApprovalError(
                "APPROVAL_BINDING_MISMATCH", "artifact or destination changed")
        evidence = Path(str(evidence_binding["path"])).resolve()
        if str(evidence) != evidence_binding.get("path"):
            raise ApprovalError(
                "APPROVAL_BINDING_MISMATCH", "evidence manifest path changed")

        _capture_file(
            decision_path, decision_snapshot, max_bytes=_CONTROL_INPUT_LIMIT,
            label="approval decision")
        _capture_file(
            approval_signature, approval_snapshot,
            max_bytes=_CONTROL_INPUT_LIMIT, label="approval signature")
        decision = _load_json(decision_snapshot, APPROVAL_DECISION_SCHEMA)
        required = {
            "request_id": request.get("request_id"),
            "operation_id": request.get("operation_id"),
            "request_sha256": request_sha256,
            "action": request.get("action"),
            "artifact_sha256": artifact_binding.get("sha256"),
            "evidence_manifest_sha256": evidence_binding.get("sha256"),
            "destination": request.get("destination"),
            "signing_identity": request.get("signing_identity"),
            "policy_version": request.get("policy_version"),
        }
        if decision.get("decision") != "approve" or any(
                decision.get(key) != value for key, value in required.items()):
            raise ApprovalError(
                "APPROVAL_BINDING_MISMATCH",
                "decision does not approve this exact action")
        verifier_home = _required_path(
            "FORMALSPECGEN_APPROVAL_GNUPGHOME", directory=True)
        _verify_detached_signature(
            decision_snapshot, approval_snapshot, gpg_home=verifier_home,
            authorized_keys=_authorized_reviewers(),
            expected_identity=str(request.get("reviewer_identity", "")), runner=runner)

        artifact_sha256, artifact_size = _capture_file(
            artifact, artifact_snapshot,
            max_bytes=_binding_limit(artifact_binding, "artifact"),
            label="artifact")
        if artifact_sha256 != artifact_binding.get("sha256") or \
                artifact_size != artifact_binding.get("size"):
            raise ApprovalError(
                "APPROVED_ARTIFACT_CHANGED", "artifact changed after approval")
        evidence_sha256, evidence_size = _capture_file(
            evidence, evidence_snapshot,
            max_bytes=_binding_limit(evidence_binding, "evidence manifest"),
            label="evidence manifest")
        if evidence_sha256 != evidence_binding.get("sha256") or \
                evidence_size != evidence_binding.get("size"):
            raise ApprovalError(
                "APPROVED_ARTIFACT_CHANGED", "evidence manifest changed")

        signing_home = _required_path(
            "FORMALSPECGEN_SIGNER_GNUPGHOME", directory=True)
        signing_key = os.environ.get("FORMALSPECGEN_SIGNING_KEY", "").strip().upper()
        if not _FULL_FINGERPRINT.fullmatch(signing_key) or \
                signing_key != str(request["signing_identity"]).upper():
            raise ApprovalError(
                "SIGNER_POLICY_UNAVAILABLE", "signing identity is unavailable")
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise ApprovalError("APPROVAL_REPLAY", "signature destination already exists")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".signature-", dir=str(output.parent))
        os.close(descriptor)
        temporary = Path(temporary_name)
        temporary.unlink()
        try:
            result = runner([
                "gpg", "--homedir", str(signing_home), "--batch", "--yes",
                "--local-user", signing_key, "--detach-sign", "--output",
                str(temporary), str(artifact_snapshot),
            ], capture_output=True, text=True)
            if result.returncode != 0 or not temporary.is_file():
                raise ApprovalError("PROTECTED_SIGNING_FAILED", "GPG signing failed")
            signer = _verify_detached_signature(
                artifact_snapshot, temporary, gpg_home=signing_home,
                authorized_keys={signing_key}, expected_identity=signing_key,
                runner=runner)
            try:
                os.link(temporary, output)
            except FileExistsError as exc:
                raise ApprovalError("APPROVAL_REPLAY", "signature already exists") from exc
            with output.open("rb") as handle:
                os.fsync(handle.fileno())
            _fsync_directory(output.parent)
        finally:
            temporary.unlink(missing_ok=True)
    signature_sha256, size = _sha256_file(output)
    return {
        "status": "SIGNED", "request_id": request["request_id"],
        "signature_sha256": signature_sha256, "signature_size": size,
        "signing_identity": signer["primary_fingerprint"],
        "signing_fingerprint": signer["signing_fingerprint"],
        "signed_artifact_sha256": artifact_sha256,
        "private_key_exposed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute an approved signing action")
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--decision", required=True, type=Path)
    parser.add_argument("--approval-signature", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = sign_approved_artifact(
            request_path=args.request, decision_path=args.decision,
            approval_signature=args.approval_signature,
            artifact=args.artifact, output=args.output)
    except ApprovalError as exc:
        print(json.dumps(exc.as_dict(), sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
