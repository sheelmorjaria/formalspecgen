# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M46: kernel composition — the orchestrator's precondition flow."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from pipeline.kernel_composition import verify_composition
from pipeline.kernel_lattice import verify_kernel

BOOT = {
    "steps": [
        {"name": "timer_init", "establishes": ["timer_running"]},
        {"name": "pool_init",
         "requires": ["timer_running"],
         "establishes": ["pools_mapped"]},
        {"name": "scheduler_start",
         "requires": ["pools_mapped"],
         "establishes": ["runqueue_ready"]},
        {"name": "net_start",
         "requires": ["runqueue_ready", "pools_mapped"],
         "establishes": ["packet_path_up"]},
    ]
}

WITNESS = open(Path(__file__).parent / "test_kernel_lattice.py").read()
WITNESS = WITNESS.split('WITNESS = """', 1)[1].split('"""', 1)[0]
ISR = """int handle(int irq) {
    int status = irq & 3;
    for (int i = 0; i < 8; i++) { status = status + 1; }
    return status;
}
"""

MEMORY_MAP = {"kernel_pools": {"object_pool": [0x4000, 0x8000]},
              "devices": {"eth": [0x10000, 0x11000]}}
CONTRACTS = {"eth": [0x10000, 0x10800]}
N150 = {"target": "n150", "memory_model": "x86_tso",
        "timing": {"max_cycles": 500}}


def _esbmc() -> bool:
    return shutil.which("esbmc") is not None


def _kernel(tmp_path, *, composition=None, boot=BOOT):
    """A two-subsystem kernel: scheduler + network, one orchestrator."""
    root = tmp_path / "kernel"
    for sub, sources in (("scheduler", [("runqueue.c", WITNESS),
                                        ("sched_tick.c", ISR)]),
                         ("net", [("rx_ring.c", WITNESS),
                                  ("timer_tick.c", ISR)])):
        sub_dir = root / sub
        sub_dir.mkdir(parents=True, exist_ok=True)
        for name, text in sources:
            (sub_dir / name).write_text(text, encoding="utf-8")
        (sub_dir / "kernel.json").write_text(json.dumps({
            "weak_memory": [sources[0][0]], "lockfree": [sources[0][0]],
            "wcet": {sources[1][0]: {}}, "dma": [],
            "memory_map": MEMORY_MAP, "dma_contracts": CONTRACTS}),
            encoding="utf-8")
    manifest = {"subsystems": ["scheduler", "net"]}
    if composition is True:
        manifest["composition"] = "composition.json"
        (root / "composition.json").write_text(
            json.dumps(boot), encoding="utf-8")
    elif composition is not None:
        manifest["composition"] = composition
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def _profile(tmp_path, raw=N150, name="n150"):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_boot_flow_proves_and_counts_preconditions():
    verdict = verify_composition(BOOT)
    assert verdict["status"] == "SYSTEM_COMPOSITION_PROVED"
    assert verdict["claim"] == "SYSTEM_COMPOSITION_PROVED"
    assert verdict["scope"] == "deterministic_precondition_flow"
    assert verdict["preconditions_checked"] == 4
    assert verdict["steps"] == ["timer_init", "pool_init",
                                "scheduler_start", "net_start"]
    assert "runqueue_ready" in verdict["facts_established"]
    assert "compose lane" in verdict["note"]   # honest scope note


def test_unmet_precondition_refuses_by_name():
    broken = {"steps": [
        {"name": "net_start", "requires": ["runqueue_ready"],
         "establishes": []}]}
    verdict = verify_composition(broken)
    assert verdict["code"] == "COMPOSITION_PRECONDITION_UNMET"
    assert "net_start" in verdict["message"]
    assert "runqueue_ready" in verdict["message"]
    # self-establishment is refused even when the fact is declared
    circular = {"steps": [
        {"name": "s", "requires": ["x"], "establishes": ["x"]}]}
    assert verify_composition(circular)["code"] == \
        "COMPOSITION_PRECONDITION_UNMET"


def test_reestablished_fact_and_residuals_refuse():
    twice = {"steps": [
        {"name": "a", "establishes": ["f"]},
        {"name": "b", "establishes": ["f"]}]}
    verdict = verify_composition(twice)
    assert verdict["code"] == "COMPOSITION_FACT_REESTABLISHED"
    assert "a" in verdict["message"] and "b" in verdict["message"]

    assert verify_composition({})["code"] == "steps_missing"
    assert verify_composition(None)["code"] == "composition_artifact_invalid"
    assert verify_composition({"steps": [{}]}["steps"] and
                              {"steps": [{}]})["code"] == "step_field_missing"
    assert verify_composition({"steps": [
        {"name": "a", "requires": "x"}]})["code"] == "step_field_missing"


def test_multi_subsystem_bundle_mints_per_subsystem(tmp_path):
    """Two subsystems, one orchestrator: every entry carries its
    subsystem; the lock-free claim is judged once PER WITNESS; the
    composition claim is minted once, arch-agnostic."""
    root = _kernel(tmp_path, composition=True)
    bundle = verify_kernel(root, [_profile(tmp_path)])
    assert bundle["status"] == "KERNEL_EVIDENCE_BUNDLE", bundle
    entries = bundle["claims"]
    composition = [e for e in entries if e["claim"] ==
                   "SYSTEM_COMPOSITION_PROVED"]
    assert len(composition) == 1
    assert composition[0]["scope"] == "deterministic_precondition_flow"
    by_sub = {}
    for e in entries:
        if e["claim"] == "LOCK_FREE_LINEARIZABILITY_PROVED":
            by_sub.setdefault(e["subsystem"], []).append(e)
    assert set(by_sub) == {"scheduler", "net"}
    if _esbmc():
        assert all(e["judge"] == "esbmc" for v in by_sub.values()
                   for e in v)
    # per-subsystem scoped claims mint under each subsystem
    wcet = {e["subsystem"] for e in entries
            if e["claim"] == "WCET_BOUND_PROVEN"}
    assert wcet == {"scheduler", "net"}


def test_broken_composition_fails_the_bundle_by_name(tmp_path):
    root = _kernel(tmp_path, composition=True,
                   boot={"steps": [{"name": "net_start",
                                    "requires": ["nothing_provides_this"]}]})
    bundle = verify_kernel(root, [_profile(tmp_path)])
    assert bundle["status"] == "KERNEL_VERIFICATION_FAILED"
    assert bundle["failures"][0]["code"] == "COMPOSITION_PRECONDITION_UNMET"
    # the per-subsystem claims gathered before the refusal survive
    assert any(e["claim"] == "LOCK_FREE_LINEARIZABILITY_PROVED"
               for e in bundle["claims"])


def test_composition_and_subsystem_residuals(tmp_path):
    assert verify_composition({"steps": [{"name": "a"}]})["status"] == \
        "SYSTEM_COMPOSITION_PROVED"   # no requirements is satisfiable
    root = _kernel(tmp_path, composition="ghost.json")
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "composition_artifact_missing"
    (root / "broken.json").write_text("{nope", encoding="utf-8")
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["composition"] = "broken.json"
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "composition_artifact_invalid"
    manifest["subsystems"] = ["scheduler", "ghost"]
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "subsystem_dir_missing"
    manifest["subsystems"] = []
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "subsystems_invalid"
    sched = root / "scheduler" / "kernel.json"
    sched.write_text("{bad", encoding="utf-8")
    manifest["subsystems"] = ["scheduler"]
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "kernel_manifest_invalid"


def test_establishes_type_and_lattice_branch_pins(tmp_path):
    assert verify_composition({"steps": [
        {"name": "a", "establishes": "f"}]})["code"] == "step_field_missing"
    # a subsystem whose kernel.json exists but is unreadable JSON
    root = _kernel(tmp_path)
    (root / "scheduler" / "kernel.json").write_text("{oops", encoding="utf-8")
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "kernel_manifest_invalid"
    # no-subsystem flat manifest still runs (back-compat shape)
    flat = _kernel(tmp_path)          # rebuild clean
    bundle = verify_kernel(flat / "scheduler", [_profile(tmp_path)])
    assert bundle["status"] in {"KERNEL_EVIDENCE_BUNDLE",
                                "KERNEL_VERIFICATION_FAILED"}
    assert all("subsystem" not in e for e in bundle.get("claims", []))


def test_duplicate_step_name_is_refused():
    """A later step sharing an earlier step's name would let the
    self-establishment check fire (established[fact] == name) —
    duplicate boot-step names are refused, provenance stays unique."""
    dup = {"steps": [{"name": "s", "establishes": ["x"]},
                     {"name": "s", "requires": ["x"]}]}
    verdict = verify_composition(dup)
    assert verdict["code"] == "COMPOSITION_PRECONDITION_UNMET"
    assert "claims to establish" in verdict["message"]
