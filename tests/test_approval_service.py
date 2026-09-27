# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import mcp_server

from pipeline.approval_service import (
    ApprovalError,
    ApprovalService,
    record_human_decision,
)
from pipeline.protected_signer import sign_approved_artifact


REVIEWER = "A" * 40
SIGNER = "B" * 40


class FakeCommands:
    def __init__(self):
        self.signer_calls = 0

    def __call__(self, command, **_kwargs):
        command = [str(item) for item in command]
        if command[0].endswith("protected-signer"):
            self.signer_calls += 1
            output = Path(command[command.index("--output") + 1])
            output.write_bytes(b"detached-signature")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "--detach-sign" in command:
            output = Path(command[command.index("--output") + 1])
            output.write_bytes(b"human-decision-signature")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "--verify" in command:
            artifact = Path(command[-1])
            identity = REVIEWER if artifact.name == "decision.json" else SIGNER
            return SimpleNamespace(
                returncode=0, stdout=f"[GNUPG:] VALIDSIG {identity} 0 0\n",
                stderr="")
        raise AssertionError(command)


def _service(tmp_path: Path, commands: FakeCommands, *, now=None) -> ApprovalService:
    signer = tmp_path / "protected-signer"
    signer.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    signer.chmod(0o700)
    verifier = tmp_path / "public-keys"
    verifier.mkdir()
    return ApprovalService(
        tmp_path / "approvals", verifier_home=verifier,
        authorized_reviewers={REVIEWER}, signer=signer,
        signing_identity=SIGNER, reviewer_identity=REVIEWER,
        runner=commands, now=now or (lambda: datetime.now(timezone.utc)))


def _request(tmp_path: Path, service: ApprovalService) -> tuple[dict, Path, Path]:
    artifact = tmp_path / "refactor.json"
    evidence = tmp_path / "manifest.json"
    artifact.write_text('{"status":"VERIFIED"}\n', encoding="utf-8")
    evidence.write_text('{"claim":"REFACTOR_CONTRACT_PRESERVED"}\n', encoding="utf-8")
    request = service.create_request(
        artifact=artifact, evidence_manifest=evidence,
        admission_profile_sha256="c" * 64,
        claim="REFACTOR_CONTRACT_PRESERVED",
        verification_status="VERIFIED", ttl_seconds=900)
    return request, artifact, evidence


def _decide(tmp_path: Path, request: dict, commands: FakeCommands, decision="approve"):
    return record_human_decision(
        tmp_path / "approvals", request["approval"]["request_id"],
        decision=decision, signing_key=REVIEWER,
        gpg_home=tmp_path / "reviewer-secret", runner=commands)


def test_approved_action_signs_once_and_keeps_verification_claim(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    _decide(tmp_path, request, commands)

    result = service.execute(request["approval"]["request_id"])
    repeated = service.execute(request["approval"]["request_id"])

    assert result["status"] == "SIGNED"
    assert result["request_satisfied"] is True
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["verification"]["claim_upgraded_by_signing"] is False
    assert result["approval"]["private_key_exposed"] is False
    assert repeated["approval_receipt"]["sha256"] == \
        result["approval_receipt"]["sha256"]
    assert commands.signer_calls == 1


def test_changed_artifact_is_rejected_before_signing(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, artifact, _ = _request(tmp_path, service)
    _decide(tmp_path, request, commands)
    artifact.write_text("changed\n", encoding="utf-8")

    with pytest.raises(ApprovalError, match="artifact changed") as error:
        service.execute(request["approval"]["request_id"])
    assert error.value.code == "APPROVED_ARTIFACT_CHANGED"
    assert commands.signer_calls == 0


def test_tampered_decision_binding_is_rejected(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)
    decision = tmp_path / "approvals" / request_id / "decision.json"
    value = json.loads(decision.read_text(encoding="utf-8"))
    value["destination"] = "/different/action"
    decision.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ApprovalError) as error:
        service.execute(request_id)
    assert error.value.code == "APPROVAL_BINDING_MISMATCH"
    assert commands.signer_calls == 0


def test_denial_is_terminal_without_signing(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    _decide(tmp_path, request, commands, decision="deny")

    result = service.execute(request["approval"]["request_id"])
    assert result["status"] == "DENIED"
    assert result["request_satisfied"] is False
    assert result["signature"] is None
    assert commands.signer_calls == 0


def test_expired_approval_is_rejected(tmp_path):
    commands = FakeCommands()
    current = datetime(2026, 1, 1, tzinfo=timezone.utc)
    service = _service(tmp_path, commands, now=lambda: current)
    request, _, _ = _request(tmp_path, service)
    _decide(tmp_path, request, commands)
    service.now = lambda: current + timedelta(hours=1)

    with pytest.raises(ApprovalError) as error:
        service.execute(request["approval"]["request_id"])
    assert error.value.code == "APPROVAL_EXPIRED"


def test_crash_after_signature_recovers_without_signing_twice(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)

    with pytest.raises(RuntimeError, match="crash"):
        service.execute(
            request_id, before_receipt=lambda: (_ for _ in ()).throw(
                RuntimeError("crash")))
    result = service.execute(request_id)
    assert result["status"] == "SIGNED"
    assert commands.signer_calls == 1


def test_concurrent_completion_invokes_signer_once(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)
    results = []

    threads = [threading.Thread(
        target=lambda: results.append(service.execute(request_id))) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert [item["status"] for item in results] == ["SIGNED", "SIGNED"]
    assert commands.signer_calls == 1


def test_human_decision_is_write_once(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    _decide(tmp_path, request, commands)
    with pytest.raises(ApprovalError) as error:
        _decide(tmp_path, request, commands)
    assert error.value.code == "APPROVAL_REPLAY"


def test_completed_receipt_rejects_later_artifact_tampering(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, artifact, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)
    assert service.execute(request_id)["status"] == "SIGNED"
    artifact.write_text("tampered after signing\n", encoding="utf-8")
    with pytest.raises(ApprovalError) as error:
        service.status(request_id)
    assert error.value.code == "APPROVED_ARTIFACT_CHANGED"


def test_completed_receipt_cannot_upgrade_verification_claim(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)
    assert service.execute(request_id)["status"] == "SIGNED"
    receipt = tmp_path / "approvals" / request_id / "receipt.json"
    value = json.loads(receipt.read_text(encoding="utf-8"))
    value["verification"]["claim"] = "UNBOUNDED_BEHAVIOR_PROVED"
    receipt.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ApprovalError) as error:
        service.status(request_id)
    assert error.value.code == "APPROVAL_STATE_INVALID"


def test_malformed_request_is_a_structured_state_failure(tmp_path):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    request_path = tmp_path / "approvals" / request_id / "request.json"
    value = json.loads(request_path.read_text(encoding="utf-8"))
    del value["artifact"]["sha256"]
    request_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ApprovalError) as error:
        service.status(request_id)
    assert error.value.code == "APPROVAL_STATE_INVALID"


def test_protected_signer_independently_rejects_expired_request(tmp_path):
    commands = FakeCommands()
    current = datetime(2025, 1, 1, tzinfo=timezone.utc)
    service = _service(tmp_path, commands, now=lambda: current)
    request, artifact, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)
    root = tmp_path / "approvals" / request_id
    with pytest.raises(ApprovalError) as error:
        sign_approved_artifact(
            request_path=root / "request.json",
            decision_path=root / "decision.json",
            approval_signature=root / "decision.json.sig",
            artifact=artifact, output=root / "artifact.sig", runner=commands)
    assert error.value.code == "APPROVAL_EXPIRED"


def test_protected_signer_revalidates_and_signs_exact_action(tmp_path, monkeypatch):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, artifact, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)
    signing_home = tmp_path / "signing-home"
    signing_home.mkdir()
    registry = tmp_path / "reviewers.json"
    registry.write_text(json.dumps({
        "keys": [{"key_id": REVIEWER}],
    }), encoding="utf-8")
    monkeypatch.setenv(
        "FORMALSPECGEN_APPROVAL_GNUPGHOME", str(tmp_path / "public-keys"))
    monkeypatch.setenv("FORMALSPECGEN_APPROVAL_TRUST_REGISTRY", str(registry))
    monkeypatch.setenv("FORMALSPECGEN_SIGNER_GNUPGHOME", str(signing_home))
    monkeypatch.setenv("FORMALSPECGEN_SIGNING_KEY", SIGNER)
    root = tmp_path / "approvals" / request_id
    output = root / "artifact.sig"

    result = sign_approved_artifact(
        request_path=root / "request.json",
        decision_path=root / "decision.json",
        approval_signature=root / "decision.json.sig",
        artifact=artifact, output=output, runner=commands)

    assert result["status"] == "SIGNED"
    assert result["request_id"] == request_id
    assert result["private_key_exposed"] is False
    assert output.read_bytes() == b"human-decision-signature"


def test_protected_signer_rejects_unapproved_destination(tmp_path, monkeypatch):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, artifact, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    _decide(tmp_path, request, commands)
    signing_home = tmp_path / "signing-home"
    signing_home.mkdir()
    registry = tmp_path / "reviewers.json"
    registry.write_text(json.dumps({
        "keys": [{"key_id": REVIEWER}],
    }), encoding="utf-8")
    monkeypatch.setenv(
        "FORMALSPECGEN_APPROVAL_GNUPGHOME", str(tmp_path / "public-keys"))
    monkeypatch.setenv("FORMALSPECGEN_APPROVAL_TRUST_REGISTRY", str(registry))
    monkeypatch.setenv("FORMALSPECGEN_SIGNER_GNUPGHOME", str(signing_home))
    monkeypatch.setenv("FORMALSPECGEN_SIGNING_KEY", SIGNER)
    root = tmp_path / "approvals" / request_id
    with pytest.raises(ApprovalError) as error:
        sign_approved_artifact(
            request_path=root / "request.json",
            decision_path=root / "decision.json",
            approval_signature=root / "decision.json.sig",
            artifact=artifact, output=tmp_path / "different.sig", runner=commands)
    assert error.value.code == "APPROVAL_BINDING_MISMATCH"


def test_mcp_status_and_completion_use_only_approval_service(monkeypatch):
    class Service:
        def status(self, request_id):
            return {"status": "PENDING", "claim": "NO_PROOF",
                    "request_satisfied": False, "request_id": request_id}

        def execute(self, request_id):
            return {
                "status": "SIGNED", "claim": "REFACTOR_CONTRACT_PRESERVED",
                "request_satisfied": True, "request_id": request_id,
                "private_key_exposed": False,
            }

    calls = []
    monkeypatch.setattr(
        mcp_server, "_configured_approval_service",
        lambda *, require_signer: calls.append(require_signer) or Service())
    pending = mcp_server.get_approval_request("a" * 32)
    signed = mcp_server.complete_refactor_signing("a" * 32)

    assert pending["status"] == "PENDING"
    assert signed["status"] == "SIGNED"
    assert signed["private_key_exposed"] is False
    assert "protected_signing" in signed["mcp_admission"]["granted_effects"]
    assert calls == [False, True]


@pytest.mark.parametrize("scenario", [
    "changed-artifact", "denied", "expired", "replayed-decision",
    "crash-recovery", "concurrent-retry",
])
def test_approval_security_acceptance_matrix(tmp_path, scenario):
    """Release evidence for the protected action's principal failure modes."""
    commands = FakeCommands()
    current = datetime(2026, 1, 1, tzinfo=timezone.utc)
    service = _service(tmp_path, commands, now=lambda: current)
    request, artifact, _ = _request(tmp_path, service)
    request_id = request["approval"]["request_id"]
    decision = "deny" if scenario == "denied" else "approve"
    _decide(tmp_path, request, commands, decision=decision)
    if scenario == "changed-artifact":
        artifact.write_text("changed\n", encoding="utf-8")
        with pytest.raises(ApprovalError, match="artifact changed"):
            service.execute(request_id)
    elif scenario == "denied":
        assert service.execute(request_id)["status"] == "DENIED"
    elif scenario == "expired":
        service.now = lambda: current + timedelta(hours=1)
        with pytest.raises(ApprovalError, match="expired"):
            service.execute(request_id)
    elif scenario == "replayed-decision":
        with pytest.raises(ApprovalError) as error:
            _decide(tmp_path, request, commands)
        assert error.value.code == "APPROVAL_REPLAY"
    elif scenario == "crash-recovery":
        with pytest.raises(RuntimeError):
            service.execute(
                request_id, before_receipt=lambda: (_ for _ in ()).throw(
                    RuntimeError("crash")))
        assert service.execute(request_id)["status"] == "SIGNED"
        assert commands.signer_calls == 1
    else:
        results = []
        threads = [threading.Thread(
            target=lambda: results.append(service.execute(request_id)))
            for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(results) == 2
        assert commands.signer_calls == 1
