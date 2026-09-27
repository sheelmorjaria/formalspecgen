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
    return keys


def sign_approved_artifact(
        *, request_path: Path, decision_path: Path,
        approval_signature: Path, artifact: Path, output: Path,
        runner=subprocess.run) -> dict[str, object]:
    """Revalidate and execute exactly one approved signing action."""
    request = _load_json(request_path, APPROVAL_REQUEST_SCHEMA)
    decision = _load_json(decision_path, APPROVAL_DECISION_SCHEMA)
    request_sha256, _ = _sha256_file(request_path)
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
                r"[0-9a-f]{64}", str(request.get("admission_profile_sha256", ""))) or \
            not isinstance(artifact_binding, dict) or \
            not isinstance(evidence_binding, dict) or \
            any(not isinstance(binding.get("path"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("sha256", ""))) or
                not isinstance(binding.get("size"), int)
                for binding in (artifact_binding, evidence_binding)):
        raise ApprovalError("APPROVAL_BINDING_MISMATCH", "unsupported approval action")
    required = {
        "request_id": request.get("request_id"),
        "operation_id": request.get("operation_id"),
        "request_sha256": request_sha256,
        "action": request.get("action"),
        "artifact_sha256": request.get("artifact", {}).get("sha256"),
        "evidence_manifest_sha256": request.get("evidence_manifest", {}).get("sha256"),
        "destination": request.get("destination"),
        "signing_identity": request.get("signing_identity"),
        "policy_version": request.get("policy_version"),
    }
    if decision.get("decision") != "approve" or any(
            decision.get(key) != value for key, value in required.items()):
        raise ApprovalError(
            "APPROVAL_BINDING_MISMATCH", "decision does not approve this exact action")

    verifier_home = _required_path(
        "FORMALSPECGEN_APPROVAL_GNUPGHOME", directory=True)
    _verify_detached_signature(
        decision_path, approval_signature, gpg_home=verifier_home,
        authorized_keys=_authorized_reviewers(),
        expected_identity=str(request.get("reviewer_identity", "")), runner=runner)

    artifact = artifact.resolve()
    output = output.resolve()
    if str(artifact) != request.get("artifact", {}).get("path") or \
            str(output) != request.get("destination"):
        raise ApprovalError("APPROVAL_BINDING_MISMATCH", "artifact or destination changed")
    artifact_sha256, artifact_size = _sha256_file(artifact)
    binding = request["artifact"]
    if artifact_sha256 != binding.get("sha256") or artifact_size != binding.get("size"):
        raise ApprovalError("APPROVED_ARTIFACT_CHANGED", "artifact changed after approval")
    evidence = Path(request["evidence_manifest"]["path"])
    evidence_sha256, evidence_size = _sha256_file(evidence)
    if evidence_sha256 != request["evidence_manifest"].get("sha256") or \
            evidence_size != request["evidence_manifest"].get("size"):
        raise ApprovalError("APPROVED_ARTIFACT_CHANGED", "evidence manifest changed")

    signing_home = _required_path("FORMALSPECGEN_SIGNER_GNUPGHOME", directory=True)
    signing_key = os.environ.get("FORMALSPECGEN_SIGNING_KEY", "").strip()
    if not signing_key or signing_key.upper() != str(request["signing_identity"]).upper():
        raise ApprovalError("SIGNER_POLICY_UNAVAILABLE", "signing identity is unavailable")
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
            str(temporary), str(artifact),
        ], capture_output=True, text=True)
        if result.returncode != 0 or not temporary.is_file():
            raise ApprovalError("PROTECTED_SIGNING_FAILED", "GPG signing failed")
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
        "signing_identity": signing_key, "private_key_exposed": False,
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
