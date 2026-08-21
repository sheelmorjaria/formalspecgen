# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M58 post-quantum TLS resource-bound lane."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from pipeline.capability_registry import capability
from pipeline.kernel_lattice import verify_kernel
from pipeline.pq_tls_pool import verify_pq_tls_pool
from pipeline.rust_support import check_rust_syntax, lint_rust


ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples/formalkernel"
NET = DEMO / "kernel/net"
PROFILES = [DEMO / "profiles/n150.json", DEMO / "profiles/r52.json"]


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.skipif(shutil.which("z3") is None, reason="real Z3 not installed")
def test_z3_proves_exact_two_handshake_ceiling_for_each_profile():
    artifact = _json(NET / "pq_tls.json")
    for profile_path in PROFILES:
        verdict = verify_pq_tls_pool(artifact, _json(profile_path))
        assert verdict["status"] == "PQ_TLS_POOL_BOUND_PROVED"
        assert verdict["capacity"] == 2
        assert verdict["session_size_bytes"] == 22208
        assert verdict["footprint_bytes"] == 44416
        assert verdict["budget_bytes"] == 49152
        assert verdict["backpressure"] == "ERR_MEM"
        assert verdict["cryptographic_strength_proved"] is False


def test_capacity_or_parameter_drift_fails_closed():
    artifact = _json(NET / "pq_tls.json")
    profile = _json(PROFILES[0])
    too_small = copy.deepcopy(artifact)
    too_small["capacity"] = 1
    assert verify_pq_tls_pool(too_small, profile)["code"] == \
        "PQ_TLS_CAPACITY_NOT_EXACT"
    too_large = copy.deepcopy(artifact)
    too_large["capacity"] = 3
    assert verify_pq_tls_pool(too_large, profile)["code"] == \
        "PQ_TLS_CAPACITY_NOT_EXACT"
    invalid = copy.deepcopy(artifact)
    invalid["session_components_bytes"]["signature"] = 0
    assert verify_pq_tls_pool(invalid, profile)["code"] == \
        "PQ_TLS_COMPONENT_SIZE_INVALID"


def test_valid_capacity_mints_nothing_when_z3_is_absent(monkeypatch):
    monkeypatch.setattr("pipeline.pq_tls_pool.shutil.which", lambda _name: None)
    verdict = verify_pq_tls_pool(_json(NET / "pq_tls.json"), _json(PROFILES[0]))
    assert verdict["status"] == "PQ_TLS_POOL_FAILED"
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["code"] == "z3_unavailable"


def test_pool_rejects_missing_and_malformed_resource_inputs():
    artifact, profile = _json(NET / "pq_tls.json"), _json(PROFILES[0])
    cases = []
    bad = copy.deepcopy(artifact); bad["profile_budgets"] = {}; cases.append((bad, "PQ_TLS_PROFILE_MISSING"))
    bad = copy.deepcopy(artifact); bad["session_components_bytes"] = {}; cases.append((bad, "PQ_TLS_COMPONENTS_MISSING"))
    bad = copy.deepcopy(artifact); bad["capacity"] = 0; cases.append((bad, "PQ_TLS_CAPACITY_INVALID"))
    bad = copy.deepcopy(artifact); bad["alignment_bytes"] = 0; cases.append((bad, "PQ_TLS_ALIGNMENT_INVALID"))
    bad = copy.deepcopy(artifact); bad["profile_budgets"]["n150"] = 0; cases.append((bad, "PQ_TLS_BUDGET_INVALID"))
    for candidate, code in cases:
        assert verify_pq_tls_pool(candidate, profile)["code"] == code


def test_z3_execution_and_non_unsat_fail_closed(monkeypatch):
    artifact, profile = _json(NET / "pq_tls.json"), _json(PROFILES[0])
    monkeypatch.setattr("pipeline.pq_tls_pool.shutil.which", lambda _name: "z3")
    monkeypatch.setattr("pipeline.pq_tls_pool.subprocess.run",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("boom")))
    assert verify_pq_tls_pool(artifact, profile)["code"] == "z3_failed"
    result = type("Result", (), {"returncode": 0, "stdout": "sat\n"})()
    monkeypatch.setattr("pipeline.pq_tls_pool.subprocess.run",
                        lambda *_args, **_kwargs: result)
    assert verify_pq_tls_pool(artifact, profile)["code"] == "PQ_TLS_CAPACITY_NOT_EXACT"


def test_pool_source_is_hash_bound_bounded_and_panic_free():
    artifact = _json(NET / "pq_tls.json")
    source = (NET / artifact["source"]).read_text(encoding="utf-8")
    assert artifact["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert "TLS_SESSION_CAPACITY: usize = 2" in source
    assert "Err(TlsPoolError::ErrMem)" in source
    assert check_rust_syntax(source)["status"] == "RUST_CHECKED"
    assert not [item for item in lint_rust(source) if item["severity"] == "error"]
    for forbidden in ("unsafe", ".unwrap(", ".expect(", "panic!("):
        assert forbidden not in source


@pytest.mark.skipif(shutil.which("z3") is None, reason="real Z3 not installed")
def test_both_bundles_mint_only_the_memory_claim_and_name_crypto_boundary():
    for manifest in ("kernel.json", "monolith.json"):
        bundle = verify_kernel(DEMO / "kernel", PROFILES, manifest)
        assert bundle["status"] == "KERNEL_EVIDENCE_BUNDLE"
        scopes = {item["scope"] for item in bundle["claims"]
                  if item["claim"] == "HARDWARE_MEMORY_BOUND_PROVED"}
        assert "pq_tls_session_pool_n150" in scopes
        assert "pq_tls_session_pool_r52" in scopes
        boundary = next(item for item in bundle["boundaries"]
                        if item["scope"] == "post_quantum_cryptographic_implementation")
        assert boundary["cryptographic_strength_proved"] is False
        assert boundary["liboqs_implementation_proved"] is False


def test_registry_forbids_cryptographic_overclaiming():
    lane = capability("m58_pq_tls").milestone
    assert lane is not None and lane.current_maturity == "bounded-evidence"
    assert lane.required_judges == ("Z3",)
    assert "CRYPTOGRAPHIC_STRENGTH_PROVED" in lane.claims_forbidden
    assert "LIBOQS_IMPLEMENTATION_PROVED" in lane.claims_forbidden
