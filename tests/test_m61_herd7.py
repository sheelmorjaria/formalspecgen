# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M61: real-judge weak-memory simulation remains fail closed."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pipeline.weak_memory as weak_memory
import pipeline.kernel_lattice as kernel_lattice
from pipeline.capability_registry import capability
from pipeline.weak_memory import herd7_model_check


def _litmus(tmp_path: Path) -> Path:
    path = tmp_path / "mp.litmus"
    path.write_text("AArch64 MP\n{}\nexists (0:X0=1)\n", encoding="utf-8")
    return path


def test_absent_judge_is_named_without_minting(monkeypatch, tmp_path):
    monkeypatch.setattr(weak_memory.shutil, "which", lambda _name: None)
    verdict = herd7_model_check(_litmus(tmp_path), "armv8_sc")
    assert verdict["status"] == "judge_pending"
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["code"] == "herd7_unavailable"


def test_never_observation_mints_hash_bound_model_claim(monkeypatch, tmp_path):
    path = _litmus(tmp_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(weak_memory.shutil, "which", lambda _name: "/bin/herd7")
    monkeypatch.setattr(weak_memory.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=0,
                                        stdout="Observation MP Never 0 1\n",
                                        stderr=""))
    verdict = herd7_model_check(path, "armv8_sc", expected_sha256=digest)
    assert verdict["status"] == "WEAK_MEMORY_SAFETY_PROVED"
    assert verdict["judge"] == "herd7"
    assert verdict["observation"] == "Never"
    assert verdict["litmus_sha256"] == digest
    assert len(verdict["output_sha256"]) == 64


def test_counterexample_and_unrecognized_results_fail_closed(monkeypatch, tmp_path):
    path = _litmus(tmp_path)
    monkeypatch.setattr(weak_memory.shutil, "which", lambda _name: "/bin/herd7")
    monkeypatch.setattr(weak_memory.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=0,
                                        stdout="Observation MP Sometimes 1 0\n",
                                        stderr=""))
    assert herd7_model_check(path, "armv8_sc")["code"] == \
        "WEAK_MEMORY_COUNTEREXAMPLE"
    monkeypatch.setattr(weak_memory.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=0, stdout="Test MP Allowed\n",
                                        stderr=""))
    assert herd7_model_check(path, "armv8_sc")["code"] == \
        "HERD7_RESULT_UNRECOGNIZED"


def test_input_drift_execution_errors_and_boundaries(monkeypatch, tmp_path):
    path = _litmus(tmp_path)
    assert herd7_model_check(path, "armv8_sc", expected_sha256="0" * 64)[
        "code"] == "LITMUS_HASH_MISMATCH"
    assert herd7_model_check(tmp_path / "missing.litmus", "armv8_sc")[
        "code"] == "input_unavailable"
    wrong = tmp_path / "mp.txt"
    wrong.write_text("x", encoding="utf-8")
    assert herd7_model_check(wrong, "armv8_sc")["code"] == \
        "UNSUPPORTED_BOUNDARY"
    assert herd7_model_check(path, "rc11")["code"] == "unknown_memory_model"
    monkeypatch.setattr(weak_memory.shutil, "which", lambda _name: "/bin/herd7")
    monkeypatch.setattr(weak_memory.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=2, stdout="", stderr="bad"))
    assert herd7_model_check(path, "armv8_sc")["code"] == \
        "HERD7_EXECUTION_FAILED"
    monkeypatch.setattr(weak_memory.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("exec")))
    assert herd7_model_check(path, "armv8_sc")["code"] == \
        "HERD7_EXECUTION_FAILED"


def test_registry_keeps_silicon_and_refinement_claims_forbidden():
    milestone = capability("m61_herd7").milestone
    assert milestone is not None
    assert milestone.required_judges == ("herd7",)
    assert milestone.step_status == "complete"
    assert milestone.current_maturity == "model-evidence"
    assert "WEAK_MEMORY_SAFETY_PROVED" in milestone.completed_claims
    assert "PHYSICAL_SILICON_MEMORY_MODEL_PROVED" in milestone.claims_forbidden


def test_repository_litmus_hashes_match_review_manifest():
    root = Path(__file__).parents[1] / "examples/formalkernel/kernel"
    import json
    manifest = json.loads((root / "weak_memory.json").read_text())
    for model in ("x86_tso", "armv8_sc"):
        spec = manifest[model]
        assert hashlib.sha256((root / spec["litmus"]).read_bytes()).hexdigest() \
            == spec["sha256"]


def test_kernel_m61_entry_preserves_judge_hashes(monkeypatch, tmp_path):
    """The bundle must not discard the real judge's cryptographic bindings."""
    root = tmp_path / "kernel"
    root.mkdir()
    (root / "ring.c").write_text("unused", encoding="utf-8")
    litmus = root / "mp.litmus"
    litmus.write_text("X86_64 MP\n{}\nforall 0:RAX=0\n", encoding="utf-8")
    digest = hashlib.sha256(litmus.read_bytes()).hexdigest()
    (root / "weak.json").write_text(
        __import__("json").dumps({"x86_tso": {
            "litmus": "mp.litmus", "sha256": digest}}), encoding="utf-8")
    (root / "kernel.json").write_text(__import__("json").dumps({
        "deployment": "microkernel", "weak_memory": ["ring.c"],
        "weak_memory_models": "weak.json"}), encoding="utf-8")
    profile = tmp_path / "n150.json"
    profile.write_text(__import__("json").dumps(
        {"target": "n150", "memory_model": "x86_tso"}), encoding="utf-8")
    monkeypatch.setattr(kernel_lattice, "barrier_correspondence",
                        lambda *_a: {"status": "BARRIER_CORRESPONDENCE_PROVED"})
    monkeypatch.setattr(kernel_lattice, "herd7_model_check", lambda *_a, **_k: {
        "status": "WEAK_MEMORY_SAFETY_PROVED", "litmus_sha256": digest,
        "output_sha256": "f" * 64, "observation": "Never",
        "epistemic_boundary": "model only"})
    bundle = kernel_lattice.verify_kernel(root, [profile])
    entry = next(item for item in bundle["claims"]
                 if item["claim"] == "WEAK_MEMORY_SAFETY_PROVED")
    assert entry["evidence"] == {
        "litmus_sha256": digest, "output_sha256": "f" * 64,
        "observation": "Never", "epistemic_boundary": "model only"}
