# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed TLC execution and publication for staged architectures."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


def validate_architecture_with_tlc(tla_file: str | Path, cfg_file: str | Path,
                                   tlc_jar: str, java: str = "java",
                                   timeout: int = 120) -> dict:
    command = [java, "-jar", tlc_jar, "-config", str(cfg_file), str(tla_file)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "exit_code": 124, "trace": "TLC timed out"}
    except OSError as exc:
        return {"status": "TOOL_MISSING", "exit_code": 127, "trace": str(exc)}
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    lowered = output.lower()
    if result.returncode == 0:
        status = "VERIFIED"
    elif "deadlock" in lowered:
        status = "DEADLOCK"
    elif "invariant" in lowered or "counterexample" in lowered:
        status = "INVARIANT_VIOLATED"
    else:
        status = "TLC_FAILED"
    return {"status": status, "exit_code": result.returncode, "trace": output[-12000:]}


def publish_architecture(artifact: dict, tlc_result: dict, out_file: str | Path,
                         evidence_file: str | Path | None = None) -> dict:
    """Publish only a TLC-verified artifact; failed results never create output files."""
    if tlc_result.get("status") != "VERIFIED":
        status = tlc_result.get("status", "UNKNOWN")
        raise ValueError(f"ARCHITECTURE_{status}: publication refused")
    destination = Path(out_file)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
    evidence = {"architecture_sha256": hashlib.sha256(payload).hexdigest(),
                "tlc_status": tlc_result, "claim": "BOUNDED_ARCHITECTURE_EVIDENCE"}
    destination.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    evidence_path = Path(evidence_file) if evidence_file else destination.with_name(
        destination.stem + ".evidence.json")
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence
