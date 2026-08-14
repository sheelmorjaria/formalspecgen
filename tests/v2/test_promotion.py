# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
from unittest.mock import patch

import pytest
import yaml

from pipeline.domain_v2 import DomainSpecV2
from pipeline.domain_v2_promotion import (
    ReviewedDomainSpecV2,
    candidate_sha256, promote_domain, verify_artifact_signature,
    promote_validated_candidate,
)
from pipeline.domain_v2_publication import TlcEvidence, ValidatedEvidence, publish_validation_success


def candidate_value():
    return {
        "schema_version": 2,
        "review_status": "unreviewed",
        "domain_name": "Switch",
        "module_name": "switch",
        "actors": 1,
        "state_variables": [{"kind": "bool", "name": "enabled", "initial": False}],
        "operations": [{
            "name": "enable", "return_type": "void", "failure_semantics": "unavailable",
            "guards": [], "effects": [{"id": "set_enabled", "target": "enabled",
                                          "value": {"kind": "boolean", "value": True}}],
            "frame": ["enabled"],
        }],
        "tlc_invariants": [{"id": "EnabledIsBoolean", "expression": {
            "kind": "or", "left": {"kind": "field", "name": "enabled"},
            "right": {"kind": "eq", "left": {"kind": "field", "name": "enabled"},
                      "right": {"kind": "boolean", "value": False}},
        }}],
    }


def write_candidate(path, value=None):
    path.write_text(json.dumps(value or candidate_value(), indent=2), encoding="utf-8")
    return DomainSpecV2.model_validate(value or candidate_value())


def write_evidence(path, digest):
    evidence = ValidatedEvidence(
        candidate_sha256=digest,
        generated_tla_sha256="b" * 64,
        execution_assumption="atomic_last_result_abstraction",
        abstraction_mode="atomic_operations",
        bounds={"enabled": 2, "actors": 1},
        state_space_upper_bound=2,
        reachable_state_count=2,
        reachable_transition_count=1,
        tools={"tlc": TlcEvidence(version="2.19", command=["java", "-jar", "tla2tools.jar", "-version"])},
        tlc_exit_status=0,
    )
    publish_validation_success(path, evidence)


def test_promotion_rejects_mismatched_human_accepted_hash(tmp_path):
    candidate_path = tmp_path / "switch.json"
    candidate = write_candidate(candidate_path)
    evidence_path = tmp_path / "switch.validation.json"
    write_evidence(evidence_path, candidate_sha256(candidate))

    with pytest.raises(ValueError, match="CRITICAL: candidate hash mismatch"):
        promote_validated_candidate(candidate_path, evidence_path, tmp_path / "reviewed.json",
                                    accept_candidate_sha256="0" * 64)


def test_promotion_requires_validation_artifact(tmp_path):
    candidate_path = tmp_path / "switch.json"
    candidate = write_candidate(candidate_path)
    with pytest.raises(FileNotFoundError):
        promote_validated_candidate(candidate_path, tmp_path / "missing.json",
                                    tmp_path / "reviewed.json",
                                    accept_candidate_sha256=candidate_sha256(candidate))


def test_promotion_rejects_evidence_for_a_different_candidate(tmp_path):
    candidate_path = tmp_path / "switch.json"
    candidate = write_candidate(candidate_path)
    evidence_path = tmp_path / "switch.validation.json"
    write_evidence(evidence_path, "c" * 64)

    with pytest.raises(ValueError, match="does not bind"):
        promote_validated_candidate(candidate_path, evidence_path, tmp_path / "reviewed.json",
                                    accept_candidate_sha256=candidate_sha256(candidate))


def test_promotion_rejects_tampered_evidence_envelope(tmp_path):
    candidate_path = tmp_path / "switch.json"
    candidate = write_candidate(candidate_path)
    evidence_path = tmp_path / "switch.validation.json"
    digest = candidate_sha256(candidate)
    write_evidence(evidence_path, digest)
    envelope = json.loads(evidence_path.read_text(encoding="utf-8"))
    envelope["evidence"]["reachable_state_count"] = 99
    evidence_path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        promote_validated_candidate(candidate_path, evidence_path, tmp_path / "reviewed.json",
                                    accept_candidate_sha256=digest)


def test_successful_promotion_records_both_accepted_hashes_without_mutating_candidate(tmp_path):
    candidate_path = tmp_path / "switch.json"
    candidate = write_candidate(candidate_path)
    original = candidate_path.read_bytes()
    digest = candidate_sha256(candidate)
    evidence_path = tmp_path / "switch.validation.json"
    destination = tmp_path / "canonical" / "switch.json"
    write_evidence(evidence_path, digest)

    reviewed = promote_validated_candidate(
        candidate_path, evidence_path, destination, accept_candidate_sha256=digest)

    assert candidate_path.read_bytes() == original
    assert reviewed.review_status == "reviewed"
    assert reviewed.accepted_candidate_sha256 == digest
    saved = ReviewedDomainSpecV2.model_validate_json(destination.read_text(encoding="utf-8"))
    assert saved == reviewed
    assert saved.accepted_evidence_sha256 == json.loads(
        evidence_path.read_text(encoding="utf-8"))["evidence_sha256"]
    assert candidate_sha256(candidate) != candidate_sha256(saved)


def test_promotion_can_emit_explicit_gpg_detached_signature(tmp_path):
    candidate_path = tmp_path / "switch.json"
    candidate = write_candidate(candidate_path)
    digest = candidate_sha256(candidate)
    evidence_path = tmp_path / "switch.validation.json"
    destination = tmp_path / "canonical" / "switch.json"
    write_evidence(evidence_path, digest)
    with patch("pipeline.domain_v2_promotion.subprocess.run") as run:
        reviewed = promote_validated_candidate(
            candidate_path, evidence_path, destination,
            accept_candidate_sha256=digest, signing_key="reviewer@example.test")
    signature = destination.with_name(destination.name + ".promotion.sig")
    assert reviewed.review_status == "reviewed"
    assert run.call_args.kwargs["check"] is True
    assert str(signature) in run.call_args.args[0]


def test_signature_verification_enforces_presence_validity_and_key_policy(tmp_path):
    artifact = tmp_path / "verdict.json"; artifact.write_text("{}")
    signature = tmp_path / "verdict.json.sig"; signature.write_text("sig")
    with patch("pipeline.domain_v2_promotion.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "[GNUPG:] GOODSIG ABC123 Reviewer"
        run.return_value.stderr = ""
        assert verify_artifact_signature(artifact, signature, {"ABC123"})["status"] == \
            "SIGNATURE_VERIFIED"
        assert verify_artifact_signature(artifact, signature, {"OTHER"})["status"] == \
            "UNAUTHORIZED_REVIEWER"
    signature.unlink()
    assert verify_artifact_signature(artifact, signature)["status"] == "SIGNATURE_MISSING"


def test_promotion_fails_closed_when_gpg_signing_fails(tmp_path):
    candidate_path = tmp_path / "switch.json"
    candidate = write_candidate(candidate_path)
    digest = candidate_sha256(candidate)
    evidence_path = tmp_path / "switch.validation.json"
    destination = tmp_path / "canonical" / "switch.json"
    write_evidence(evidence_path, digest)
    with patch("pipeline.domain_v2_promotion.subprocess.run", side_effect=OSError("gpg missing")):
        with pytest.raises(ValueError, match="signature generation failed"):
            promote_validated_candidate(candidate_path, evidence_path, destination,
                                        accept_candidate_sha256=digest, signing_key="key")


def test_promotion_rejects_already_reviewed_candidate(tmp_path):
    value = candidate_value()
    value["review_status"] = "reviewed"
    candidate_path = tmp_path / "reviewed.json"
    candidate = write_candidate(candidate_path, value)
    evidence_path = tmp_path / "reviewed.validation.json"
    write_evidence(evidence_path, candidate_sha256(candidate))

    with pytest.raises(ValueError, match="only an unreviewed"):
        promote_validated_candidate(candidate_path, evidence_path, tmp_path / "out.json",
                                    accept_candidate_sha256=candidate_sha256(candidate))


def test_promotion_loads_canonical_candidate_from_yaml(tmp_path):
    candidate_path = tmp_path / "switch.yaml"
    candidate_path.write_text(yaml.safe_dump(candidate_value(), sort_keys=False), encoding="utf-8")
    candidate = DomainSpecV2.model_validate(candidate_value())
    digest = candidate_sha256(candidate)
    evidence_path = tmp_path / "switch.validation.json"
    destination = tmp_path / "switch.reviewed.json"
    write_evidence(evidence_path, digest)

    reviewed = promote_validated_candidate(
        candidate_path, evidence_path, destination, accept_candidate_sha256=digest)

    assert reviewed.accepted_candidate_sha256 == digest


def test_named_promotion_wrapper_builds_v2_registry_path_and_protects_existing(tmp_path):
    reviewed = object()
    with patch("pipeline.domain_v2_promotion.promote_validated_candidate",
               return_value=reviewed) as promote:
        assert promote_domain("switch", accept_candidate_sha256="a" * 64,
                              project_root=tmp_path) is reviewed
    args = promote.call_args.args
    assert args[0] == tmp_path / "domains/candidates/switch.v2.yaml"
    assert args[1].name == "switch.v2.validation.json"
    assert args[2] == tmp_path / "domains/v2/switch.json"
    args[2].parent.mkdir(parents=True); args[2].write_text("reviewed")
    with pytest.raises(FileExistsError, match="already exists"):
        promote_domain("switch", accept_candidate_sha256="a" * 64, project_root=tmp_path)
    with patch("pipeline.domain_v2_promotion.promote_validated_candidate",
               return_value=reviewed):
        assert promote_domain("switch", accept_candidate_sha256="a" * 64,
                              project_root=tmp_path, replace_reviewed=True) is reviewed
    with pytest.raises(ValueError, match="safe module"):
        promote_domain("../escape", accept_candidate_sha256="a" * 64,
                       project_root=tmp_path)
