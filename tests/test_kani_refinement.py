# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M53: the Kani refinement lane — judge, named refusals, lattice."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pipeline.kani_refinement import KANI_AVAILABLE, verify_rust_refinement

PROOFS = Path("examples/formalkernel/boot/proofs")
LIB = (PROOFS / "src" / "lib.rs").read_text()


def _crate(tmp_path, lib_text):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text(lib_text, encoding="utf-8")
    return tmp_path


def test_structural_refusals_need_no_kani(tmp_path):
    """The gate names its refusals before the availability check."""
    assert verify_rust_refinement(tmp_path / "nope")["code"] == \
        "proofs_dir_missing"
    empty = tmp_path / "empty"; empty.mkdir()
    assert verify_rust_refinement(empty)["code"] == "proof_crate_missing"
    # a proof over a COPY is a proof of nothing: the lane refuses any
    # harness not #[path]-bound to the image's own witness.rs
    unlinked = _crate(tmp_path / "unlinked",
                      LIB.replace('#[path = "../../src/witness.rs"]\n', ""))
    assert verify_rust_refinement(unlinked)["code"] == "WITNESS_LINK_MISSING"
    # an empty proof crate is the vacuous refusal
    vacuous = _crate(tmp_path / "vacuous",
                     '#[path = "../../src/witness.rs"]\npub mod witness;\n')
    assert verify_rust_refinement(vacuous)["code"] == "harnesses_missing"


def test_mocked_residuals_fail_closed(tmp_path, monkeypatch):
    """With availability patched True and cargo kani mocked, every
    failure mode refuses by name (the c846ef5 canon — patched, never
    undone)."""
    from unittest.mock import patch
    from pipeline import kani_refinement
    monkeypatch.setattr(kani_refinement, "KANI_AVAILABLE", True)
    crate = _crate(tmp_path / "crate", LIB)

    def run_mock(args, cwd=None, **kw):
        return subprocess.CompletedProcess(
            args, 1, stdout="error: could not compile", stderr="")
    with patch("pipeline.kani_refinement.subprocess.run", run_mock):
        assert verify_rust_refinement(crate)["code"] == "build_failed"

    def run_failed(args, cwd=None, **kw):
        return subprocess.CompletedProcess(
            args, 0, stdout="Verification failed for - ring_harness\n"
            "Complete - 2 successfully verified harnesses, "
            "1 failures, 3 total.", stderr="")
    with patch("pipeline.kani_refinement.subprocess.run", run_failed):
        verdict = verify_rust_refinement(crate)
        assert verdict["code"] == "HARNESS_FAILED"
        assert verdict["harnesses_failed"] == ["ring_harness"]

    with patch("pipeline.kani_refinement.subprocess.run",
               side_effect=subprocess.TimeoutExpired("cargo kani", 600)):
        assert verify_rust_refinement(crate)["code"] == "kani_timeout"

    with patch("pipeline.kani_refinement.subprocess.run",
               side_effect=OSError("segv")):
        assert verify_rust_refinement(crate)["code"] == "kani_crashed"

    # a summary line with failures but no named harness still refuses
    def run_summary_fail(args, cwd=None, **kw):
        return subprocess.CompletedProcess(
            args, 1, stdout="Complete - 2 successfully verified "
            "harnesses, 1 failures, 3 total.", stderr="")
    with patch("pipeline.kani_refinement.subprocess.run", run_summary_fail):
        assert verify_rust_refinement(crate)["code"] == \
            "kani_verification_failed"

    # fewer verified harnesses than #[kani::proof] functions: a
    # harness was silently dropped
    def run_dropped(args, cwd=None, **kw):
        return subprocess.CompletedProcess(
            args, 0, stdout="Complete - 2 successfully verified "
            "harnesses, 0 failures, 3 total.", stderr="")
    with patch("pipeline.kani_refinement.subprocess.run", run_dropped):
        verdict = verify_rust_refinement(crate)
        assert verdict["code"] == "kani_verification_failed"
        assert "silently dropped" in verdict["message"]


def test_lane_degrades_to_pending_without_kani(tmp_path, monkeypatch):
    """An absent judge NEVER mints — the claim is named judge_pending."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from test_kernel_composition import _kernel, _profile
    from pipeline import kani_refinement
    from pipeline.kernel_lattice import verify_kernel
    monkeypatch.setattr(kani_refinement, "KANI_AVAILABLE", False)
    root = _kernel(tmp_path)
    for mf_path in root.rglob("kernel.json"):
        mf = json.loads(mf_path.read_text())
        changed = False
        for key in ("lockfree", "mpsc"):
            if mf.pop(key, None) is not None:
                changed = True
        if changed:
            mf_path.write_text(json.dumps(mf))
    (root / "proofs").mkdir(parents=True)
    (root / "proofs" / "Cargo.toml").write_text("[package]\n")
    (root / "proofs" / "src").mkdir()
    (root / "proofs" / "src" / "lib.rs").write_text(LIB)
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["kani_proofs"] = "proofs"
    (root / "kernel.json").write_text(json.dumps(manifest))
    bundle = verify_kernel(root, [_profile(tmp_path)])
    entry = [e for e in bundle["claims"]
             if e["claim"] == "RUST_WITNESS_REFINEMENT_PROVED"]
    assert entry and entry[0]["status"] == "judge_pending"


def test_lane_residuals(tmp_path):
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from test_kernel_composition import _kernel, _profile
    from pipeline.kernel_lattice import verify_kernel
    root = _kernel(tmp_path)
    for mf_path in root.rglob("kernel.json"):
        mf = json.loads(mf_path.read_text())
        changed = False
        for key in ("lockfree", "mpsc"):
            if mf.pop(key, None) is not None:
                changed = True
        if changed:
            mf_path.write_text(json.dumps(mf))
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["kani_proofs"] = "ghost"
    (root / "kernel.json").write_text(json.dumps(manifest))
    failed = verify_kernel(root, [_profile(tmp_path)])
    assert failed["code"] == "proofs_dir_missing"


@pytest.mark.skipif(not KANI_AVAILABLE, reason="kani not installed")
def test_real_kani_proves_the_image_witness():
    """Real cargo kani: the harnesses #[path]-include the image's own
    witness.rs and every one verifies."""
    verdict = verify_rust_refinement(PROOFS)
    assert verdict["status"] == "RUST_WITNESS_REFINEMENT_PROVED"
    assert verdict["judge"] == "kani"
    assert verdict["harnesses_verified"] >= 3
    assert "path-included, not a copy" in verdict["witness_source"]


@pytest.mark.skipif(not KANI_AVAILABLE, reason="kani not installed")
def test_demo_bundle_mints_the_refinement_claim():
    from pipeline.kernel_lattice import verify_kernel
    bundle = verify_kernel("examples/formalkernel/kernel",
                           ["examples/formalkernel/profiles/n150.json",
                            "examples/formalkernel/profiles/r52.json"])
    assert bundle["status"] == "KERNEL_EVIDENCE_BUNDLE"
    claims = {e["claim"] for e in bundle["claims"]}
    assert "RUST_WITNESS_REFINEMENT_PROVED" in claims
    assert len(bundle["claims"]) == 53
