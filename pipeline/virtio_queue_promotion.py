# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Human, hash-bound promotion for the M86.3 virtio queue model."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from . import config
from .verus_evidence import erase_overlay
from .virtio_queue_model import validate_queue_model


CLAIM = "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _run_verus(source: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    result = subprocess.run(
        [config.VERUS_BIN, "--no-cheating", "--output-json", str(source)],
        capture_output=True, text=True, timeout=60, check=False)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {}
    return result, payload


def _output_sha256(result: subprocess.CompletedProcess[str]) -> str:
    return _sha256_bytes((result.stdout + result.stderr).encode())


_MUTATIONS = (
    ("bad_constructor", "Self { port, in_flight: 0 }", "Self { port, in_flight: 1 }"),
    ("submit_no_increment", "self.in_flight += 1;", "self.in_flight += 0;"),
    ("queue_full_returns_success",
     "return Err(DriverError::QueueFull);", "return Ok(());"),
    ("complete_no_decrement", "self.in_flight -= 1;", "self.in_flight -= 0;"),
    ("empty_complete_returns_success",
     "return Err(DriverError::UnexpectedCompletion);", "return Ok(());"),
    ("weakened_submit_model",
     "if accepted { pre + 1 } else { pre }", "if accepted { pre } else { pre }"),
)


def promote_virtio_queue_model(
    project_root: str | Path, *, accept_candidate_sha256: str,
) -> dict[str, Any]:
    """Promote only after replaying identity, judge, and anti-vacuity gates."""
    root = Path(project_root).resolve()
    directory = root / "examples/formalkernel/kernel/verus_virtio"
    candidate_path = directory / "queue_model.candidate.json"
    validation_path = directory / "queue_model.validation.json"
    overlay_path = directory / "virtio_blk_overlay.rs"
    production_path = root / "examples/formalkernel/kernel/vfs/virtio_blk.rs"
    reviewed_path = directory / "queue_model.reviewed.json"
    bridge_path = directory / "model_bridge.json"

    actual_hash = _sha256(candidate_path)
    if accept_candidate_sha256 != actual_hash:
        raise ValueError("CRITICAL: candidate hash mismatch")
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    replayed_validation = validate_queue_model(candidate_path)
    if replayed_validation["status"] != "VALIDATED_CANDIDATE":
        raise ValueError("queue model structural validation failed")
    if validation.get("candidate_sha256") != actual_hash or validation.get("errors"):
        raise ValueError("stored validation does not bind the accepted candidate")
    if candidate["human_review"].get("accepted"):
        raise ValueError("candidate must remain unreviewed; promote the separate artifact")

    overlay_text = overlay_path.read_text(encoding="utf-8")
    if actual_hash not in overlay_text:
        raise ValueError("Verus overlay does not bind the accepted candidate")
    if erase_overlay(overlay_text).encode() != production_path.read_bytes():
        raise ValueError("VERUS_OVERLAY_DRIFT")
    positive, positive_payload = _run_verus(overlay_path)
    results = positive_payload.get("verification-results", {})
    if positive.returncode != 0 or results.get("verified", 0) <= 0 or results.get("errors", 0):
        raise ValueError("Verus bridge replay failed")

    mutation_results = []
    with tempfile.TemporaryDirectory(prefix="formalspecgen-m86-promote-") as temp:
        temporary_root = Path(temp)
        for mutation_id, before, after in _MUTATIONS:
            mutated_text = overlay_text.replace(before, after, 1)
            if mutated_text == overlay_text:
                raise ValueError(f"mutation anchor missing: {mutation_id}")
            mutated_path = temporary_root / f"{mutation_id}.rs"
            mutated_path.write_text(mutated_text, encoding="utf-8")
            result, payload = _run_verus(mutated_path)
            if result.returncode == 0:
                raise ValueError(f"VERUS_MUTATION_SURVIVED: {mutation_id}")
            mutation_results.append({
                "id": mutation_id,
                "source_sha256": _sha256(mutated_path),
                "output_sha256": _output_sha256(result),
                "exit_code": result.returncode,
                "reported_verified": payload.get("verification-results", {}).get("verified", 0),
            })

    reviewed = {
        **candidate,
        "status": "REVIEWED",
        "human_review": {
            "accepted": True,
            "accepted_candidate_sha256": actual_hash,
        },
    }
    _write_json_atomic(reviewed_path, reviewed)
    bridge = {
        "schema_version": 1,
        "lane": "M86.3_reviewed_queue_model_refinement",
        "status": CLAIM,
        "claim": CLAIM,
        "scope": "production_virtio_blk_queue_accounting",
        "candidate_model_sha256": actual_hash,
        "reviewed_model": reviewed_path.relative_to(root).as_posix(),
        "reviewed_model_sha256": _sha256(reviewed_path),
        "validation_sha256": _sha256(validation_path),
        "production_source_sha256": _sha256(production_path),
        "overlay_source_sha256": _sha256(overlay_path),
        "state_relation": "model.outstanding == rust.queue_depth()",
        "judge": {
            "name": "verus",
            "invocation": ["verus", "--no-cheating", "--output-json"],
            "exit_code": positive.returncode,
            "reported_verified": results.get("verified"),
            "reported_errors": results.get("errors"),
            "output_sha256": _output_sha256(positive),
        },
        "anti_vacuity": {
            "executed": len(mutation_results),
            "rejected": len(mutation_results),
            "mutations": mutation_results,
        },
        "external_boundaries": [
            "virtio device behavior", "interrupt delivery", "DMA completion",
            "virtio protocol semantics", "external I/O correctness",
        ],
        "claims_locked": [
            "DRIVER_DEVICE_BEHAVIOR_PROVED", "EXTERNAL_IO_SAFETY_PROVED",
            "RUST_IMPLEMENTATION_REFINEMENT_PROVED",
            "COMPILER_REFINEMENT_CHAIN_PROVED",
            "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED",
        ],
    }
    _write_json_atomic(bridge_path, bridge)
    return bridge
