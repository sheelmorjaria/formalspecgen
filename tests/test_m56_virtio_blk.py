# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M56: confined virtio-blk external-adapter boundary."""
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.dma_isolation import dma_isolation
from pipeline.ipc_nameserver import verify_ipc_table
from pipeline.rust_support import check_rust_syntax
from pipeline.syscall_boundary import verify_syscall_boundary


ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples/formalkernel"
KERNEL = DEMO / "kernel"


def _json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_virtio_adapter_compiles_but_remains_explicitly_unverified():
    source = (KERNEL / "vfs/virtio_blk.rs").read_text()
    assert source.startswith("// UNVERIFIED EXTERNAL BOUNDARY")
    assert check_rust_syntax(source)["status"] == "RUST_CHECKED"
    assert "unsafe" not in source
    assert ".unwrap()" not in source and ".expect(" not in source
    assert "REQUEST_CAPACITY: u8 = 2" in source


def test_block_dma_call_is_confined_on_every_declared_profile():
    witness = KERNEL / "vfs/virtio_blk_dma.c"
    for profile_name in ("n150", "r52"):
        profile = _json(DEMO / f"profiles/{profile_name}.json")
        verdict = dma_isolation(
            witness, profile["memory_map"], profile["dma_contracts"])
        assert verdict["status"] == "DMA_ISOLATION_PROVED"
        assert verdict["dma_calls_checked"] == 1
        assert verdict["contracts"]["blk_dev"] == [71680, 72192]


def test_storage_route_is_bounded_and_passes_only_the_syscall_door():
    syscall = _json(KERNEL / "syscalls.json")
    ipc = _json(KERNEL / "ipc.json")
    block = next(item for item in syscall["syscalls"] if item["id"] == 103)
    assert block == {"id": 103, "name": "block_submit",
                     "handler": "sys_block_submit", "resources": ["blk_ring"]}
    for profile_name in ("n150", "r52"):
        profile = _json(DEMO / f"profiles/{profile_name}.json")
        assert verify_syscall_boundary(
            {**syscall, "memory_map": profile["mmu_map"]})["status"] == \
            "SYSCALL_BOUNDARY_PROVED"
    routed = verify_ipc_table(ipc, syscall)
    assert routed["status"] == "IPC_ENDPOINT_TABLE_PROVED"
    assert routed["endpoints_checked"] == 3
    assert routed["message_pool_capacity"] == routed["total_slots"] == 6


def test_m56_registry_preserves_the_external_io_ceiling():
    lane = capability("m56_virtio_blk").milestone
    assert lane is not None and lane.step_status == "complete"
    assert lane.current_maturity == "boundary-contained"
    assert "UNVERIFIED_EXTERNAL_ADAPTER" in lane.completed_claims
    assert "EXTERNAL_IO_SAFETY_PROVED" in lane.claims_forbidden
