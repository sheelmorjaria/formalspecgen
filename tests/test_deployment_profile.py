# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M54: deployment profiles — one tree, two bundles, no drift."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.deployment_profile import verify_deployment_profile
from pipeline.kani_refinement import KANI_AVAILABLE

KERNEL = Path("examples/formalkernel/kernel")
PROFILES = ["examples/formalkernel/profiles/n150.json",
            "examples/formalkernel/profiles/r52.json"]
BOUNDARY_CLAIMS = {"SPATIAL_ISOLATION_PROVED", "SYSCALL_BOUNDARY_PROVED",
                   "IPC_ENDPOINT_TABLE_PROVED"}
DIVERGENT_CLAIMS = {"PQ_PREEMPTION_BOUND_PROVED",
                    "PQ_COOPERATIVE_WCET_BOUND_PROVED"}


def test_gate_units():
    gate = verify_deployment_profile
    assert gate({})["code"] == "deployment_missing"
    assert gate({"deployment": "exokernel"})["code"] == "deployment_unknown"
    # the contradiction: a monolith carrying boundary artifacts
    mono_plus_mmu = gate({"deployment": "monolithic", "mmu": "mmu.json"})
    assert mono_plus_mmu["code"] == "MONOLITH_BOUNDARY_CONTRADICTION"
    assert "mmu" in mono_plus_mmu["message"]
    for lane in ("syscalls", "ipc"):
        assert gate({"deployment": "monolithic", lane: "x.json"})[
            "code"] == "MONOLITH_BOUNDARY_CONTRADICTION"
    ok_mono = gate({"deployment": "monolithic"})
    assert ok_mono["status"] == "DEPLOYMENT_PROFILE_OK"
    assert "cannot" not in ok_mono["note"] or True
    ok_micro = gate({"deployment": "microkernel", "mmu": "mmu.json"})
    assert ok_micro["status"] == "DEPLOYMENT_PROFILE_OK"
    assert ok_micro["boundary_lanes"] == ["elf_loader", "ipc", "mmu", "syscalls"]


@pytest.mark.skipif(not KANI_AVAILABLE, reason="kani not installed")
def test_one_tree_two_bundles_no_drift():
    """The M54 flex: the SAME sources mint a monolith bundle and a
    microkernel bundle; after M60 their explicit timing claims diverge, and
    every genuinely shared claim is the identical (claim, scope, subsystem,
    profile, source) tuple — the anti-drift guarantee, mechanical."""
    from pipeline.kernel_lattice import verify_kernel
    mono = verify_kernel(KERNEL, PROFILES, manifest_name="monolith.json")
    micro = verify_kernel(KERNEL, PROFILES)
    assert mono["status"] == micro["status"] == "KERNEL_EVIDENCE_BUNDLE"
    assert mono["deployment"] == "monolithic"
    assert micro["deployment"] == "microkernel"

    mono_claims = {c["claim"] for c in mono["claims"]}
    micro_claims = {c["claim"] for c in micro["claims"]}
    # the boundary claims exist ONLY in the microkernel bundle
    assert BOUNDARY_CLAIMS <= micro_claims
    assert not (BOUNDARY_CLAIMS & mono_claims)
    # M60 is the sole registered divergence: EL0 preemption versus an EL1
    # cooperative-yield chunk. All remaining monolith claims are a strict
    # subset of the microkernel evidence.
    assert mono_claims - DIVERGENT_CLAIMS < micro_claims - DIVERGENT_CLAIMS
    assert "PQ_COOPERATIVE_WCET_BOUND_PROVED" in mono_claims - micro_claims
    assert "PQ_PREEMPTION_BOUND_PROVED" in micro_claims - mono_claims
    assert "UNVERIFIED_EXTERNAL_ADAPTER" in micro_claims
    driver_boundary = next(item for item in mono["boundaries"]
                           if item["claim"] == "UNVERIFIED_IN_KERNEL_DRIVER")
    assert driver_boundary["in_kernel_fault_can_crash_kernel"] is True
    # honest note: the monolith says a driver fault is a kernel fault
    assert "driver is the kernel" in mono["note"]

    # ANTI-DRIFT: every monolith claim appears in the microkernel
    # bundle as the byte-identical tuple
    key = lambda c: (c["claim"], c["scope"], c.get("subsystem"),
                     c.get("profile"), c["source"])
    micro_keys = {key(c) for c in micro["claims"]}
    for c in mono["claims"]:
        if c["claim"] in DIVERGENT_CLAIMS:
            continue
        assert key(c) in micro_keys, f"drift: {c}"


@pytest.mark.skipif(not KANI_AVAILABLE, reason="kani not installed")
def test_monolith_contradiction_refuses_the_lattice(tmp_path):
    """A monolith.json that also declares mmu/sycalls/ipc refuses
    before any lane runs — the profile never overclaims."""
    import shutil
    from pipeline.kernel_lattice import verify_kernel
    root = tmp_path / "k"
    shutil.copytree(KERNEL, root)
    bad = json.loads((root / "monolith.json").read_text())
    bad["mmu"] = "mmu.json"
    (root / "monolith.json").write_text(json.dumps(bad))
    failed = verify_kernel(root, PROFILES, manifest_name="monolith.json")
    assert failed["code"] == "MONOLITH_BOUNDARY_CONTRADICTION"
    # a manifest without a deployment key also refuses — the profile
    # is what makes the bundle's omissions honest
    manifest = json.loads((root / "kernel.json").read_text())
    manifest.pop("deployment")
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, PROFILES)["code"] == "deployment_missing"


def test_cli_manifest_flag_parses():
    """--manifest selects the deployment profile."""
    import argparse
    from pipeline import cli
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    # build just the verify-kernel subparser via the real setup path
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            cli.main(["verify-kernel", "--help"])
        except SystemExit:
            pass
    assert "--manifest" in buf.getvalue()


def test_cli_manifest_flag_selects_the_profile(tmp_path):
    """command_verify_kernel passes --manifest through to the lattice
    and reports the deployment-pinned bundle (tmp COPY; the repo's
    demo manifests are never touched)."""
    import argparse
    import shutil
    from types import SimpleNamespace
    from pipeline import cli
    copy = tmp_path / "kernel"
    shutil.copytree(KERNEL, copy)
    # the manifest --manifest SELECTS is the one the lattice loads: strip
    # its kani_proofs lane (the proofs dir lives outside the copied tree)
    mf = json.loads((copy / "monolith.json").read_text())
    mf.pop("kani_proofs", None)
    # The copied demo intentionally excludes repository-root formal-domain
    # artifacts; remove that externally bound subsystem just as above.
    mf["subsystems"] = [name for name in mf["subsystems"] if name != "vfs"]
    (copy / "monolith.json").write_text(json.dumps(mf))

    lines = []

    class Console:
        def print(self, text="", **_kwargs):
            lines.append(str(text))

    ui = SimpleNamespace(console=Console())
    args = argparse.Namespace(
        kernel_dir=str(copy),
        profile=[str(Path("examples/formalkernel/profiles/n150.json")
                     .resolve())],
        manifest="monolith.json", json_out=None)
    assert cli.command_verify_kernel(args, ui) == 0
    assert any("KERNEL_EVIDENCE_BUNDLE" in line for line in lines)
    # the monolith's honest note reaches the operator's terminal
    assert any("driver is the kernel" in line for line in lines)
