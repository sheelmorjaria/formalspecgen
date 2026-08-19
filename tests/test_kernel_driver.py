# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M45: the kernel-driver boundary — glue is proposed, never trusted."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from pipeline.dependency_injection import inject_dependency

STUB = """// UNVERIFIED EXTERNAL BOUNDARY
pub struct XNicDriver;

pub trait DriverPort {
    fn start(&self) -> i32;
}

impl DriverPort for XNicDriver {
    #[requires(true)]
    #[ensures(ret >= 0)]
    fn start(&self) -> i32 { 0 }
}
"""

DMA_PROFILE = {
    "memory_map": {"kernel_pools": {"object_pool": [0x4000, 0x8000]},
                   "devices": {"nic": [0x10000, 0x11000]}},
    "dma_contracts": {"nic": [0x10000, 0x10800]},
}


def _adapter(tmp_path, body):
    source = tmp_path / "xnic.rs"
    source.write_text(STUB.replace("fn start(&self) -> i32 { 0 }",
                                   f"fn start(&self) -> i32 {{ {body} }}"),
                      encoding="utf-8")
    return source


def _fill(candidate_body):
    """A deterministic stand-in for the LLM proposal: mirrors the real
    _chat_fn(provider) -> (messages, model, temperature) transport."""
    candidate = STUB.replace("fn start(&self) -> i32 { 0 }",
                             f"fn start(&self) -> i32 {{ {candidate_body} }}")

    def fake_transport(provider, *_args, **_kwargs):
        def chat(_messages, _model, _temperature):
            return candidate, "test", {}
        return chat
    return fake_transport


def test_happy_path_injects_and_checks_the_contract(tmp_path):
    """The glue lands marked UNVERIFIED_EXTERNAL_ADAPTER with the DMA
    contract checked and the Port interface immutable."""
    source = _adapter(tmp_path, "dma_map(nic, 0x100) as i32")
    with patch("pipeline.dependency_injection._chat_fn",
               _fill("dma_map(nic, 0x100) as i32")):
        result = inject_dependency(source, "kernel-driver",
                                   dma_profile=DMA_PROFILE)
    assert result["status"] == "INJECTED"
    assert result["claim"] == "UNVERIFIED_EXTERNAL_ADAPTER"
    assert result["external_io_safety_proved"] is False
    assert result["dma_contract_checked"] is True
    assert result["port_interface"] == "immutable"
    assert result["language"] == "rust"
    assert "UNVERIFIED EXTERNAL BOUNDARY" in source.read_text()


def test_glue_that_widens_the_contract_never_lands(tmp_path):
    """A proposal mapping 0x4000 bytes (past nic's 0x800 contract window,
    into the kernel pool) is refused and the stub is left untouched."""
    source = _adapter(tmp_path, "dma_map(nic, 0x100) as i32")
    original = source.read_text()
    with patch("pipeline.dependency_injection._chat_fn",
               _fill("dma_map(nic, 0x4000) as i32")):
        result = inject_dependency(source, "kernel-driver",
                                   dma_profile=DMA_PROFILE)
    assert result["status"] == "FAIL"
    assert result["code"] == "DMA_CONTRACT_VIOLATED"
    assert any("exceeds its contract" in v for v in result["violations"])
    assert source.read_text() == original   # the adapter never landed


def test_profile_is_required_fail_closed(tmp_path):
    source = _adapter(tmp_path, "0")
    assert inject_dependency(source, "kernel-driver")["code"] == \
        "dma_profile_required"
    assert inject_dependency(source, "kernel-driver",
                             dma_profile={"memory_map": {}})["code"] == \
        "dma_profile_required"


def test_surface_and_boundary_guards_still_hold(tmp_path):
    """A proposal that mutates the trusted Port surface is refused even
    when the DMA calls are clean."""
    source = _adapter(tmp_path, "0")
    mutated = STUB.replace("fn start(&self) -> i32",
                           "fn start(&self, extra: i32) -> i32")

    def mutated_transport(_provider, *_a, **_k):
        def chat(_messages, _model, _temperature):
            return mutated, "test", {}
        return chat
    with patch("pipeline.dependency_injection._chat_fn",
               mutated_transport):
        result = inject_dependency(source, "kernel-driver",
                                   dma_profile=DMA_PROFILE)
    assert result["code"] == "adapter_surface_changed"
    no_marker = _adapter(tmp_path, "0").read_text().replace(
        "// UNVERIFIED EXTERNAL BOUNDARY\n", "")
    bare = tmp_path / "bare.rs"
    bare.write_text(no_marker, encoding="utf-8")
    assert inject_dependency(bare, "kernel-driver",
                             dma_profile=DMA_PROFILE)["code"] == \
        "not_external_adapter"
    c_file = tmp_path / "x.c"
    c_file.write_text("int adapter(void);\n", encoding="utf-8")
    assert inject_dependency(c_file, "kernel-driver",
                             dma_profile=DMA_PROFILE)["code"] == \
        "unsupported_dependency"


def test_cli_routes_kernel_driver_with_profile(tmp_path):
    """The CLI reads the dma profile and refuses unreadable ones."""
    import pipeline.cli as cli
    source = _adapter(tmp_path, "dma_map(nic, 0x100) as i32")
    profile = tmp_path / "dma.json"
    profile.write_text(json.dumps(DMA_PROFILE), encoding="utf-8")
    with patch("pipeline.dependency_injection._chat_fn",
               _fill("dma_map(nic, 0x100) as i32")):
        rc = cli.main(["implement", str(source),
                       "--dependencies", "kernel-driver",
                       "--dma-profile", str(profile), "--json",
                       str(tmp_path / "out.json")])
    assert rc == 0
    rc = cli.main(["implement", str(source),
                   "--dependencies", "kernel-driver"])
    assert rc == 1   # dma_profile_required fails closed
    rc = cli.main(["implement", str(source),
                   "--dependencies", "kernel-driver",
                   "--dma-profile", str(tmp_path / "ghost.json")])
    assert rc == 2   # unreadable profile is a usage error


def test_malformed_memory_map_and_unparseable_calls_refuse(tmp_path):
    source = _adapter(tmp_path, "0")
    bad_map = {"memory_map": {"kernel_pools": {"p": [9, 4]}},
               "dma_contracts": {"nic": [0, 4]}}
    assert inject_dependency(source, "kernel-driver",
                             dma_profile=bad_map)["code"] == \
        "memory_map_incomplete"
    # a DMA-shaped token the checker cannot parse never passes vacuously
    source2 = _adapter(tmp_path, "dma_map_page_region(nic, x) as i32")
    with patch("pipeline.dependency_injection._chat_fn",
               _fill("dma_map_page_region(nic, x) as i32")):
        result = inject_dependency(source2, "kernel-driver",
                                   dma_profile=DMA_PROFILE)
    assert result["code"] == "dma_callsite_unrecognized"
