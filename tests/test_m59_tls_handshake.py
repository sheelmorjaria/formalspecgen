# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M59 bounded TLS handshake state-machine evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.kernel_lattice import verify_kernel
from pipeline.tls_handshake import (render_tls_handshake,
                                    verify_tls_handshake_evidence)


ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples/formalkernel"
NET = DEMO / "kernel/net"
PROFILES = [DEMO / "profiles/n150.json", DEMO / "profiles/r52.json"]


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_tlc_evidence_is_bound_to_source_and_generated_model():
    artifact = _json(NET / "tls_handshake.json")
    evidence = _json(NET / artifact["validation"])
    source = (NET / artifact["source"]).read_bytes()
    verdict = verify_tls_handshake_evidence(artifact, source, evidence)
    assert verdict["status"] == "TLS_HANDSHAKE_EVIDENCE_BOUND"
    assert verdict["distinct_states"] == 5
    assert verdict["states_generated"] == 9
    assert verdict["tlc_version"].startswith("2.19")


def test_renderer_emits_fair_progress_and_explicit_terminal_states():
    artifact = _json(NET / "tls_handshake.json")
    tla, cfg = render_tls_handshake(artifact)
    assert "WF_vars(Next)" in tla
    assert 'TerminalStates == {"Established", "Failed"}' in tla
    assert "PROPERTY EventuallyTerminal" in cfg
    assert "INVARIANT Initialized" in cfg


def test_transition_or_source_drift_refuses_prior_evidence():
    artifact = _json(NET / "tls_handshake.json")
    evidence = _json(NET / artifact["validation"])
    source = (NET / artifact["source"]).read_bytes()
    changed = copy.deepcopy(artifact)
    changed["transitions"][0]["to"] = "Failed"
    assert verify_tls_handshake_evidence(changed, source, evidence)["code"] == \
        "TLS_EVIDENCE_BINDING_MISMATCH"
    assert verify_tls_handshake_evidence(artifact, source + b"\n", evidence)["code"] == \
        "TLS_EVIDENCE_BINDING_MISMATCH"
    dead_end = copy.deepcopy(artifact)
    dead_end["transitions"] = [item for item in dead_end["transitions"]
                                if item["from"] != "Finished"]
    with pytest.raises(ValueError, match="TLS_DEAD_END_STATE"):
        render_tls_handshake(dead_end)


def test_both_profiles_share_model_evidence_without_crypto_overclaim():
    for manifest in ("kernel.json", "monolith.json"):
        bundle = verify_kernel(DEMO / "kernel", PROFILES, manifest)
        assert bundle["status"] == "KERNEL_EVIDENCE_BUNDLE"
        assert any(item["claim"] == "BOUNDED_ARCHITECTURE_EVIDENCE"
                   and item["scope"] == "tls_handshake_tlc"
                   for item in bundle["claims"])
        boundary = next(item for item in bundle["boundaries"]
                        if item["claim"] == "TLS_HANDSHAKE_REFINEMENT_PENDING")
        assert boundary["cryptographic_strength_proved"] is False
        assert boundary["transcript_authenticity_proved"] is False
        assert boundary["mbedtls_implementation_refinement_proved"] is False


def test_registry_keeps_native_and_crypto_claims_locked():
    lane = capability("m59_tls_handshake").milestone
    assert lane is not None and lane.required_judges == ("TLC",)
    assert lane.current_maturity == "bounded-evidence"
    assert "TLS_TRANSCRIPT_AUTHENTICITY_PROVED" in lane.claims_forbidden
    assert "MBEDTLS_IMPLEMENTATION_REFINEMENT_PROVED" in lane.claims_forbidden
