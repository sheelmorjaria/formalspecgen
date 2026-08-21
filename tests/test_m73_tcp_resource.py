# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.tcp_resource import (render_tcp_resource_model,
                                   verify_tcp_resource_evidence)


ROOT = Path("examples/formalkernel/kernel/net")
ARTIFACT = json.loads((ROOT / "tcp_resource.json").read_text())
EVIDENCE = json.loads((ROOT / "tcp_resource.validation.json").read_text())


def test_real_tlc_tcp_envelope_is_hash_bound():
    verdict = verify_tcp_resource_evidence(ARTIFACT, EVIDENCE)
    assert verdict["status"] == "TCP_RESOURCE_EVIDENCE_BOUND"
    assert verdict["claim"] == "TCP_RESOURCE_CONTAINMENT_PROVED"
    assert verdict["distinct_states"] == 49
    assert verdict["rfc9293_conformance_proved"] is False
    assert verdict["rfc5961_conformance_proved"] is False
    assert verdict["implementation_refinement_proved"] is False


def test_model_covers_sequence_windows_rst_and_partitioned_quotas():
    tla, cfg = render_tcp_resource_model("TcpResourceContainment", 4, 2, 8, 2)
    for action in ("DuplicateSyn", "ReorderedAck", "DroppedAck",
                   "RetransmitTimeout", "BlindRst", "ExpireTimeWait"):
        assert action in tla
    assert "(ack + SeqMod - expected) % SeqMod" in tla
    assert "INVARIANT LegitimateReserve" in cfg
    assert "INVARIANT PerClientQuota" in cfg


def test_quota_or_evidence_drift_fails_closed():
    artifact = copy.deepcopy(ARTIFACT)
    artifact["per_client_quota"] = 4
    assert verify_tcp_resource_evidence(artifact, EVIDENCE)["claim"] == "NO_PROOF"
    evidence = copy.deepcopy(EVIDENCE)
    evidence["generated_tla_sha256"] = "0" * 64
    assert verify_tcp_resource_evidence(ARTIFACT, evidence)["code"] == \
        "TCP_RESOURCE_EVIDENCE_BINDING_MISMATCH"


def test_m73_registry_keeps_rfc_and_native_claims_locked():
    milestone = capability("m73_tcp_resource_containment").milestone
    assert milestone is not None
    assert milestone.completed_claims == ("TCP_RESOURCE_CONTAINMENT_PROVED",)
    assert milestone.step_status == "partial"
    assert "RFC9293_CONFORMANCE_PROVED" in milestone.claims_forbidden
    assert "RFC5961_CONFORMANCE_PROVED" in milestone.claims_forbidden
    assert "TCP_IMPLEMENTATION_REFINEMENT_PROVED" in milestone.claims_forbidden
