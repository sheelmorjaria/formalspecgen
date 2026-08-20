# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M50: the IPC name server — table gate, MPSC judge, lattice lane."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.ipc_nameserver import verify_ipc_table
from pipeline.lockfree import ESBMC_AVAILABLE, verify_mpsc

ARTIFACT = {
    "message_pool": {"capacity": 4, "slot_bytes": 8},
    "endpoints": [
        {"name": "console", "id": 101, "syscall": 101, "lanes": 2,
         "slots": 4},
    ],
}
SYSCALLS = {
    # carries a memory_map so the M49 syscalls lane passes and the
    # IPC lane's refusals surface under their own names
    "memory_map": {"kernel_pools": {"k": [0, 0x1000]},
                   "user_frames": [0x10000, 0x20000]},
    "kernel_resources": {"ipc_pool": [0x2000, 0x3000]},
    "user_image": {"start": 0x10000, "end": 0x11000},
    "syscalls": [{"id": 101, "handler": "sys_ipc_send",
                  "resources": ["ipc_pool"]}],
}


def test_table_proves_with_routing():
    verdict = verify_ipc_table(ARTIFACT, SYSCALLS)
    assert verdict["status"] == "IPC_ENDPOINT_TABLE_PROVED"
    assert verdict["claim"] == "IPC_ENDPOINT_TABLE_PROVED"
    assert verdict["scope"] == "deterministic_capacity_partition"
    assert verdict["endpoints_checked"] == 1
    assert verdict["total_slots"] == 4


def test_routing_refuses_without_and_around_the_boundary():
    # no dispatch table supplied: a route the gate cannot check
    assert verify_ipc_table(ARTIFACT, None)["code"] == \
        "ENDPOINT_SYSCALL_TABLE_MISSING"
    # a route the table does not declare: a boundary bypass
    unrouted = {**ARTIFACT, "endpoints": [
        {**ARTIFACT["endpoints"][0], "syscall": 999}]}
    assert verify_ipc_table(unrouted, SYSCALLS)["code"] == \
        "ENDPOINT_SYSCALL_UNROUTED"


def test_identity_and_partition_defects_refuse():
    dup_id = {**ARTIFACT, "endpoints": [
        ARTIFACT["endpoints"][0],
        {**ARTIFACT["endpoints"][0], "name": "other", "syscall": 101}]}
    assert verify_ipc_table(dup_id, SYSCALLS)["code"] == \
        "ENDPOINT_ID_CONFLICT"
    dup_name = {**ARTIFACT, "endpoints": [
        ARTIFACT["endpoints"][0],
        {**ARTIFACT["endpoints"][0], "id": 102, "syscall": 102}]}
    assert verify_ipc_table(dup_name, {"syscalls": SYSCALLS["syscalls"] + [
        {"id": 102, "handler": "h", "resources": []}]})["code"] == \
        "ENDPOINT_NAME_CONFLICT"
    unencodable = {**ARTIFACT, "endpoints": [
        {**ARTIFACT["endpoints"][0], "id": 70000}]}
    assert verify_ipc_table(unencodable, SYSCALLS)["code"] == \
        "ENDPOINT_ID_UNENCODABLE"
    # a single-producer endpoint: the MPSC claim would be vacuous
    spsc = {**ARTIFACT, "endpoints": [
        {**ARTIFACT["endpoints"][0], "lanes": 1}]}
    assert verify_ipc_table(spsc, SYSCALLS)["code"] == "ENDPOINT_NOT_MPSC"
    uneven = {**ARTIFACT, "endpoints": [
        {**ARTIFACT["endpoints"][0], "lanes": 3}]}
    assert verify_ipc_table(uneven, SYSCALLS)["code"] == \
        "SLOT_PARTITION_UNEVEN"


def test_capacity_closes_by_arithmetic():
    # one endpoint beyond the pool
    exceeds = {**ARTIFACT, "endpoints": [
        {**ARTIFACT["endpoints"][0], "slots": 8}]}
    assert verify_ipc_table(exceeds, SYSCALLS)["code"] == \
        "ENDPOINT_SLOTS_EXCEED_POOL"
    # each endpoint fits; the SUM does not — the (pool+1)-th message is
    # rejected by the table, not by hope
    over = {**ARTIFACT, "endpoints": [
        {**ARTIFACT["endpoints"][0], "id": 101, "syscall": 101,
         "slots": 4},
        {**ARTIFACT["endpoints"][0], "id": 102, "syscall": 102,
         "name": "net", "slots": 4}]}
    assert verify_ipc_table(over, {"syscalls": SYSCALLS["syscalls"] + [
        {"id": 102, "handler": "h", "resources": []}]})["code"] == \
        "POOL_OVERSUBSCRIBED"


def test_table_residuals_refuse():
    gate = verify_ipc_table
    assert gate({})["code"] == "endpoints_missing"
    assert gate({**ARTIFACT, "endpoints": []})["code"] == \
        "endpoints_missing"
    assert gate({k: v for k, v in ARTIFACT.items()
                 if k != "message_pool"})["code"] == \
        "message_pool_invalid"
    assert gate({**ARTIFACT, "message_pool": {"capacity": 0}})[
        "code"] == "message_pool_invalid"
    assert gate({**ARTIFACT, "endpoints": ["nope"]})["code"] == \
        "endpoint_field_invalid"


def test_mpsc_judge_structural_refusals(tmp_path):
    """The judge refuses shapes it cannot prove — no esbmc needed."""
    good = Path("examples/formalkernel/kernel/ipc/mpsc.c").read_text()
    mismatch = good.replace("#define CAP 2", "#define CAP 3")
    p = tmp_path / "mismatch.c"; p.write_text(mismatch)
    assert verify_mpsc(p)["code"] == "PARTITION_MISMATCH"
    # two producers on ONE lane head: the unprovable MPMC shape
    shared = good.replace("head[1] = h + 1;", "head[0] = h + 1;")
    p2 = tmp_path / "shared.c"; p2.write_text(shared)
    assert verify_mpsc(p2)["code"] == "LANE_OWNER_CONFLICT"
    # the SPSC witness is not the MPSC dialect
    assert verify_mpsc(
        "examples/formalkernel/kernel/net/rx_ring.c")["code"] == \
        "no_mpsc_structure"
    assert verify_mpsc(tmp_path / "nope.c")["code"] == "input_unavailable"


@pytest.mark.skipif(not ESBMC_AVAILABLE, reason="esbmc not installed")
def test_mpsc_judge_real_esbmc_both_directions(tmp_path):
    """Real ESBMC: the witness proves, and the judge is not decorative —
    an overfilling witness FAILS."""
    verdict = verify_mpsc("examples/formalkernel/kernel/ipc/mpsc.c")
    assert verdict["status"] == "MPSC_BOUNDED_PARTITION_PROVED"
    assert verdict["lane_owners"] == {0: "user_send", 1: "driver_send"}
    assert verdict["capacity"] == 2

    good = Path("examples/formalkernel/kernel/ipc/mpsc.c").read_text()
    broken = good.replace(
        "if (h - tail[0] < LANE_CAP)", "if (h - tail[0] <= LANE_CAP)")
    broken = broken.replace(
        "if (h - tail[1] < LANE_CAP)", "if (h - tail[1] <= LANE_CAP)")
    broken = broken.replace("for (int i = 0; i < LANE_CAP; i++)",
                            "for (int i = 0; i < LANE_CAP + 1; i++)")
    p = tmp_path / "broken.c"; p.write_text(broken)
    assert verify_mpsc(p)["code"] == "esbmc_verification_failed"


def test_lattice_ipc_lane_residuals(tmp_path):
    """The verify-kernel ipc lane refuses by name and mints through the
    M49 dispatch table."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from test_kernel_composition import _kernel, _profile
    from pipeline.kernel_lattice import verify_kernel
    root = _kernel(tmp_path)
    # strip the heavy lanes: this test judges the IPC lane wiring
    for mf_path in root.rglob("kernel.json"):
        mf = json.loads(mf_path.read_text())
        changed = False
        for key in ("lockfree", "mpsc"):
            if mf.pop(key, None) is not None:
                changed = True
        if changed:
            mf_path.write_text(json.dumps(mf))
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["syscalls"] = "syscalls.json"
    (root / "syscalls.json").write_text(json.dumps(SYSCALLS))
    manifest["ipc"] = "ghost.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "ipc_artifact_missing"
    (root / "bad.json").write_text("{nope", encoding="utf-8")
    manifest["ipc"] = "bad.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "ipc_artifact_invalid"
    (root / "ipc.json").write_text(json.dumps(ARTIFACT))
    manifest["ipc"] = "ipc.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    bundle = verify_kernel(root, [_profile(tmp_path)])
    assert any(e["claim"] == "IPC_ENDPOINT_TABLE_PROVED"
               for e in bundle.get("claims", []))
    # an unrouted endpoint fails the bundle by name
    (root / "ipc.json").write_text(json.dumps(unrouted := {
        **ARTIFACT, "endpoints": [
            {**ARTIFACT["endpoints"][0], "syscall": 999}]}))
    failed = verify_kernel(root, [_profile(tmp_path)])
    assert failed["code"] == "ENDPOINT_SYSCALL_UNROUTED"


@pytest.mark.skipif(not ESBMC_AVAILABLE, reason="esbmc not installed")
def test_demo_bundle_mints_m50_claims():
    """The current demo includes the routed M50 and M56 storage lanes."""
    from pipeline.kernel_lattice import verify_kernel
    bundle = verify_kernel("examples/formalkernel/kernel",
                           ["examples/formalkernel/profiles/n150.json",
                            "examples/formalkernel/profiles/r52.json"])
    assert bundle["status"] == "KERNEL_EVIDENCE_BUNDLE"
    claims = {e["claim"] for e in bundle["claims"]}
    assert "MPSC_BOUNDED_PARTITION_PROVED" in claims
    assert "IPC_ENDPOINT_TABLE_PROVED" in claims
    assert "SYSCALL_BOUNDARY_PROVED" in claims
    assert "UNVERIFIED_EXTERNAL_ADAPTER" in claims
    # M57 adds three ELF entries, M58 two bounds, M59 one model, M60 two WCET scopes.
    assert len(bundle["claims"]) in (37, 38)
    if "RUST_WITNESS_REFINEMENT_PROVED" in claims:
        assert len(bundle["claims"]) == 38


def test_mpsc_judge_more_residuals(tmp_path):
    """The remaining named refusals — structural, no judge needed."""
    good = Path("examples/formalkernel/kernel/ipc/mpsc.c").read_text()
    # a non-.c source is outside the lane's boundary
    p = tmp_path / "w.txt"; p.write_text(good)
    assert verify_mpsc(p)["code"] == "UNSUPPORTED_BOUNDARY"
    # one producer is the SPSC shape: no MPSC harness
    single = good.replace(
        '    pthread_create(&driver, 0, driver_send, 0);\n', "")
    p2 = tmp_path / "single.c"; p2.write_text(single)
    assert verify_mpsc(p2)["code"] == "no_thread_harness"
    no_join = good.replace("    pthread_join(user, 0);\n", "") \
                     .replace("    pthread_join(driver, 0);\n", "")
    p3 = tmp_path / "nojoin.c"; p3.write_text(no_join)
    assert verify_mpsc(p3)["code"] == "no_thread_harness"
    # a producer that never stores its lane head: no linearization point
    silent = good.replace("            head[0] = h + 1;            "
                          "/* linearization point */\n", "")
    p4 = tmp_path / "silent.c"; p4.write_text(silent)
    assert verify_mpsc(p4)["code"] == "LINEARIZATION_POINT_MISSING"
    # two stores in one producer: no single designated atomic step
    two = good.replace("            head[0] = h + 1;            "
                       "/* linearization point */\n",
                       "            head[0] = h + 1;\n"
                       "            head[0] = h + 2;\n")
    p5 = tmp_path / "two.c"; p5.write_text(two)
    assert verify_mpsc(p5)["code"] == "LINEARIZATION_MULTIPLE_STORES"
    # a producer writing a lane index beyond LANES
    oob = good.replace("head[1] = h + 1;", "head[5] = h + 1;")
    p6 = tmp_path / "oob.c"; p6.write_text(oob)
    assert verify_mpsc(p6)["code"] == "LANE_INDEX_OUT_OF_RANGE"
    # a producer touching the consumer's tail (it still owns its head
    # store, so the refusal is named for the tail alone)
    tainter = good.replace(
        "head[1] = h + 1;            /* linearization point */",
        "head[1] = h + 1;            /* linearization point */\n"
        "            tail[1] = 0;")
    p7 = tmp_path / "taint.c"; p7.write_text(tainter)
    assert verify_mpsc(p7)["code"] == "PRODUCER_WRITES_TAIL"
    # slots below lanes: a lane with no slot can never carry a message
    starved = {**ARTIFACT, "endpoints": [
        {**ARTIFACT["endpoints"][0], "slots": 1}]}
    assert verify_ipc_table(starved, SYSCALLS)["code"] == \
        "SLOTS_BELOW_LANES"


def test_mpsc_lane_degrades_to_pending_without_esbmc(tmp_path, monkeypatch):
    """An absent judge NEVER mints: the MPSC claim is named but stays
    judge_pending (the c846ef5 discipline — patched, never undone)."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from test_kernel_composition import _kernel, _profile
    from pipeline import kernel_lattice
    from pipeline.kernel_lattice import verify_kernel
    root = _kernel(tmp_path)
    (root / "ipc").mkdir()
    (root / "ipc" / "kernel.json").write_text(
        json.dumps({"mpsc": ["mpsc.c"]}))
    (root / "ipc" / "mpsc.c").write_text(
        Path("examples/formalkernel/kernel/ipc/mpsc.c").read_text())
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["subsystems"].append("ipc")
    for key in ("lockfree",):
        for mf_path in root.rglob("kernel.json"):
            mf = json.loads(mf_path.read_text())
            if mf.pop(key, None) is not None:
                mf_path.write_text(json.dumps(mf))
    (root / "kernel.json").write_text(json.dumps(manifest))
    monkeypatch.setattr("pipeline.lockfree.ESBMC_AVAILABLE", False)
    bundle = verify_kernel(root, [_profile(tmp_path)])
    entry = [e for e in bundle["claims"]
             if e["claim"] == "MPSC_BOUNDED_PARTITION_PROVED"]
    assert entry and entry[0]["status"] == "judge_pending"


def test_ipc_lane_requires_the_syscalls_artifact(tmp_path):
    """An ipc manifest whose dispatch-table artifact is missing refuses
    by name — routing cannot be half-checked."""
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
    manifest["syscalls"] = "ghost-sys.json"
    manifest["ipc"] = "ipc.json"
    (root / "ipc.json").write_text(json.dumps(ARTIFACT))
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "syscalls_artifact_missing"


def test_spsc_judge_refuses_the_mpmc_shape(tmp_path):
    """Two producers on one scalar head: the M36 SPSC dialect's own
    named fence (a shared-head enqueue is not approximated)."""
    from pipeline.lockfree import verify_lockfree
    mpmc = ("#include <pthread.h>\n#define CAP 4\nint buf[CAP];\n"
            "int head = 0;\nint tail = 0;\n"
            "void *p1(void *a){(void)a; head = head + 1; return 0;}\n"
            "void *p2(void *a){(void)a; head = head + 1; return 0;}\n"
            "int main(void){pthread_t t1, t2;\n"
            "pthread_create(&t1, 0, p1, 0);\n"
            "pthread_create(&t2, 0, p2, 0);\n"
            "pthread_join(t1, 0);\npthread_join(t2, 0);\nreturn 0;}\n")
    p = tmp_path / "mpmc.c"; p.write_text(mpmc)
    assert verify_lockfree(p)["code"] == "mpmc_not_in_dialect"
    # the partitioned MPSC witness is NOT the SPSC dialect either
    assert verify_lockfree(
        "examples/formalkernel/kernel/ipc/mpsc.c")["code"] == \
        "no_ring_structure"


def test_lattice_more_residuals(tmp_path):
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
    # a declared subsystem directory that does not exist
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["subsystems"].append("ghost")
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "subsystem_dir_missing"
    # a subsystem directory without its own kernel.json
    (root / "ghost").mkdir()
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "kernel_manifest_missing"
    # a witness the MPSC judge refuses structurally fails the bundle
    manifest["subsystems"].remove("ghost")
    manifest["syscalls"] = "syscalls.json"
    manifest["ipc"] = "ipc.json"
    (root / "syscalls.json").write_text(json.dumps(SYSCALLS))
    (root / "ipc.json").write_text(json.dumps(ARTIFACT))
    (root / "ipc_sub").mkdir()
    (root / "ipc_sub" / "kernel.json").write_text(
        json.dumps({"mpsc": ["bad.c"]}))
    (root / "ipc_sub" / "bad.c").write_text(
        Path("examples/formalkernel/kernel/ipc/mpsc.c").read_text().replace(
            "#define CAP 2", "#define CAP 3"))
    manifest["subsystems"].append("ipc_sub")
    (root / "kernel.json").write_text(json.dumps(manifest))
    failed = verify_kernel(root, [_profile(tmp_path)])
    assert failed["code"] == "PARTITION_MISMATCH"
