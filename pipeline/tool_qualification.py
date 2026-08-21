# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M75 non-circular qualification-support evidence gate."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "TOOL_QUALIFICATION_EVIDENCE_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_tool_qualification_evidence(artifact_path: str | Path,
                                       oracle_path: str | Path) -> dict:
    artifact_path, oracle_path = Path(artifact_path), Path(oracle_path)
    try:
        artifact_raw = artifact_path.read_bytes()
        artifact = json.loads(artifact_raw)
        oracle_raw = oracle_path.read_bytes()
    except (OSError, ValueError, TypeError) as exc:
        return _fail("TOOL_QUALIFICATION_ARTIFACT_INVALID", str(exc))
    if artifact.get("scope") != "reviewed_golden_vector_corpus_only" \
            or artifact.get("oracle_independence") != "stdlib_only_no_pipeline_imports":
        return _fail("TOOL_QUALIFICATION_SCOPE_INVALID")
    if artifact.get("external_authority_reviewed") is not False \
            or artifact.get("do330_qualified") is not False \
            or artifact.get("general_transformation_correctness_proved") is not False:
        return _fail("TOOL_QUALIFICATION_OVERCLAIM")
    if b"pipeline" in oracle_raw or b"formalspec" in oracle_raw:
        return _fail("ORACLE_IMPORTS_SYSTEM_UNDER_TEST")
    try:
        run = subprocess.run([sys.executable, str(oracle_path), str(artifact_path)],
                             capture_output=True, text=True, timeout=30)
        output = json.loads(run.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return _fail("INDEPENDENT_ORACLE_EXECUTION_FAILED", str(exc))
    if run.returncode != 0 or output.get("status") != "INDEPENDENT_ORACLE_PASSED":
        return _fail(output.get("code", "INDEPENDENT_ORACLE_FAILED"),
                     output.get("vector", run.stderr))
    return {
        "status": "TOOL_QUALIFICATION_EVIDENCE_READY",
        "claim": "TOOL_QUALIFICATION_EVIDENCE_READY",
        "judge": "independent_stdlib_oracle",
        "scope": artifact["scope"],
        "vectors_passed": output["vectors_passed"],
        "vector_count": output["vector_count"],
        "artifact_sha256": hashlib.sha256(artifact_raw).hexdigest(),
        "oracle_sha256": hashlib.sha256(oracle_raw).hexdigest(),
        "external_authority_reviewed": False,
        "do330_qualified": False,
        "general_transformation_correctness_proved": False,
    }
