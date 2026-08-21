# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M65 bounded multi-server capability routing judged by Z3."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def verify_server_capabilities(path: str | Path) -> dict:
    artifact_path = Path(path)
    try:
        raw = artifact_path.read_bytes()
        artifact = json.loads(raw)
        servers = artifact["servers"]
        routes = artifact["routes"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"status": "CAPABILITY_TABLE_FAILED", "claim": "NO_PROOF",
                "code": "CAPABILITY_ARTIFACT_INVALID", "message": str(exc)}
    if servers != {"vfs": ["file_descriptor"], "net": ["raw_packet"],
                   "shell": ["file_descriptor", "network_client"]}:
        return {"status": "CAPABILITY_TABLE_FAILED", "claim": "NO_PROOF",
                "code": "CAPABILITY_POLICY_MISMATCH"}
    expected_routes = [
        {"from": "shell", "to": "vfs", "capability": "file_descriptor"},
        {"from": "shell", "to": "net", "capability": "network_client"},
    ]
    if routes != expected_routes:
        return {"status": "CAPABILITY_TABLE_FAILED", "claim": "NO_PROOF",
                "code": "CAPABILITY_ROUTES_INVALID"}
    z3 = shutil.which("z3")
    if z3 is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "z3_unavailable", "judge_pending": "z3"}
    smt = """(declare-datatypes () ((Server vfs net shell)))
(declare-datatypes () ((Capability file_descriptor raw_packet network_client)))
(declare-fun allowed (Server Capability) Bool)
(assert (allowed vfs file_descriptor))
(assert (not (allowed vfs raw_packet)))
(assert (allowed net raw_packet))
(assert (not (allowed net file_descriptor)))
(assert (allowed shell file_descriptor))
(assert (allowed shell network_client))
(assert (or (allowed vfs raw_packet) (allowed net file_descriptor)))
(check-sat)
"""
    try:
        run = subprocess.run([z3, "-in"], input=smt, capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "CAPABILITY_TABLE_FAILED", "claim": "NO_PROOF",
                "code": "Z3_EXECUTION_FAILED", "message": str(exc)}
    if run.returncode != 0 or not run.stdout.lstrip().startswith("unsat"):
        return {"status": "CAPABILITY_TABLE_FAILED", "claim": "NO_PROOF",
                "code": "CAPABILITY_NONINTERFERENCE_FAILED"}
    return {"status": "SERVER_CAPABILITY_NONINTERFERENCE_PROVED",
            "claim": "SERVER_CAPABILITY_NONINTERFERENCE_PROVED",
            "judge": "z3", "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "smt_sha256": hashlib.sha256(smt.encode()).hexdigest(),
            "servers": sorted(servers), "route_count": len(routes),
            "vfs_raw_packet": False, "net_file_descriptor": False}
