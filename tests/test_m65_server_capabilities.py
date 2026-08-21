# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
import shutil
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.server_capabilities import verify_server_capabilities


ARTIFACT = Path("examples/formalkernel/kernel/server_capabilities.json")


@pytest.mark.skipif(shutil.which("z3") is None, reason="z3 not installed")
def test_real_z3_proves_reviewed_server_policy():
    verdict = verify_server_capabilities(ARTIFACT)
    assert verdict["status"] == "SERVER_CAPABILITY_NONINTERFERENCE_PROVED"
    assert verdict["judge"] == "z3"
    assert verdict["vfs_raw_packet"] is False
    assert verdict["net_file_descriptor"] is False
    assert len(verdict["artifact_sha256"]) == 64
    assert len(verdict["smt_sha256"]) == 64


def test_server_or_route_policy_drift_fails_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["servers"]["vfs"].append("raw_packet")
    drifted = tmp_path / "server_capabilities.json"
    drifted.write_text(json.dumps(artifact))
    assert verify_server_capabilities(drifted)["code"] == \
        "CAPABILITY_POLICY_MISMATCH"

    artifact = json.loads(ARTIFACT.read_text())
    artifact["routes"][0]["to"] = "net"
    drifted.write_text(json.dumps(artifact))
    assert verify_server_capabilities(drifted)["code"] == \
        "CAPABILITY_ROUTES_INVALID"


def test_m65_registry_records_claim_ceiling():
    milestone = capability("m65_server_capabilities").milestone
    assert milestone is not None
    assert milestone.required_judges == ("Z3",)
    assert milestone.completed_claims == \
        ("SERVER_CAPABILITY_NONINTERFERENCE_PROVED",)
    assert "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED" in \
        milestone.claims_forbidden
    assert "HARDWARE_CAPABILITY_ENFORCEMENT_PROVED" in \
        milestone.claims_forbidden
