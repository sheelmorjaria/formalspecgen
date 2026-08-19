# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M43: the multi-architecture kernel evidence lattice."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from pipeline.kernel_lattice import verify_kernel

# A barriered SPSC ring: passes the weak-memory correspondence gate
# (ordering primitives in both thread bodies) AND is the lock-free
# witness (one single-word store per shared index; smp_mb is a defined
# no-op so the ESBMC link succeeds under the SC pthread model).
WITNESS = """#include <pthread.h>
#define CAP 4
int buf[CAP];
int head = 0;
int tail = 0;
void smp_mb(void) {}

void *producer(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int h = head;
        if (h - tail < CAP) {
            buf[h % CAP] = i;
            smp_mb();
            head = h + 1;
        }
    }
    return 0;
}

void *consumer(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int t = tail;
        if (t < head) {
            buf[t % CAP];
            smp_mb();
            tail = t + 1;
        }
    }
    return 0;
}

int main(void) {
    pthread_t p, c;
    pthread_create(&p, 0, producer, 0);
    pthread_create(&c, 0, consumer, 0);
    pthread_join(p, 0);
    pthread_join(c, 0);
    return 0;
}
"""

ISR = """int handle(int irq) {
    int status = irq & 3;
    for (int i = 0; i < 8; i++) { status = status + 1; }
    return status;
}
"""

DMA_DRIVER = "void *eth_setup(void) { return dma_map(eth, 0x100); }\n"

MEMORY_MAP = {"kernel_pools": {"object_pool": [0x4000, 0x8000]},
              "devices": {"eth": [0x10000, 0x11000]}}
CONTRACTS = {"eth": [0x10000, 0x10800]}

N150 = {"target": "n150", "memory_model": "x86_tso",
        "timing": {"max_cycles": 500}}
R52 = {"target": "r52", "memory_model": "armv8_sc",
       "timing": {"max_cycles": 500},
       "cost_model": {"instruction": 2}}


def _kernel(tmp_path, *, ring=WITNESS, manifest_extra=None):
    root = tmp_path / "kernel"
    root.mkdir()
    (root / "ring.c").write_text(ring, encoding="utf-8")
    (root / "isr.c").write_text(ISR, encoding="utf-8")
    (root / "eth.c").write_text(DMA_DRIVER, encoding="utf-8")
    manifest = {"weak_memory": ["ring.c"], "lockfree": ["ring.c"],
                "wcet": {"isr.c": {}}, "dma": ["eth.c"],
                "memory_map": MEMORY_MAP, "dma_contracts": CONTRACTS}
    manifest.update(manifest_extra or {})
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def _profile(tmp_path, raw, name):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _esbmc() -> bool:
    return shutil.which("esbmc") is not None


def test_two_profiles_mint_scope_tagged_claims(tmp_path):
    """One kernel, two architectures: BARRIER_CORRESPONDENCE_PROVED is
    minted TWICE (x86_tso + armv8_sc scopes), the lock-free witness is
    judged ONCE, and every absent judge stays pending by name."""
    root = _kernel(tmp_path)
    bundle = verify_kernel(root, [_profile(tmp_path, N150, "n150"),
                                  _profile(tmp_path, R52, "r52")])
    assert bundle["status"] == "KERNEL_EVIDENCE_BUNDLE", bundle
    entries = {(e["claim"], e["scope"]): e for e in bundle["claims"]}
    assert ("BARRIER_CORRESPONDENCE_PROVED", "x86_tso") in entries
    assert ("BARRIER_CORRESPONDENCE_PROVED", "armv8_sc") in entries
    assert entries[("WCET_BOUND_PROVEN", "static_cfg_cost_model_n150")][
        "profile"] == "n150"
    assert ("DMA_ISOLATION_PROVED",
            "deterministic_range_disjointness_r52") in entries
    pending_wm = entries[("WEAK_MEMORY_SAFETY_PROVED", "x86_tso")]
    assert pending_wm["status"] == "judge_pending"
    assert pending_wm["judge_pending"] == "herd7_or_rc11"
    lockfree = [e for e in bundle["claims"]
                if e["claim"] == "LOCK_FREE_LINEARIZABILITY_PROVED"]
    assert len(lockfree) == 1  # arch-agnostic: judged once
    if _esbmc():
        assert lockfree[0]["judge"] == "esbmc"
    else:
        assert lockfree[0]["status"] == "judge_pending"


def test_scope_deduplication_across_sources(tmp_path):
    """Two weak-memory sources under one profile mint ONE scoped entry —
    the scope is the claim's scope, not a per-source row."""
    root = _kernel(tmp_path)
    (root / "ring2.c").write_text(WITNESS, encoding="utf-8")
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["weak_memory"] = ["ring.c", "ring2.c"]
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    bundle = verify_kernel(root, [_profile(tmp_path, N150, "n150")])
    wm = [e for e in bundle["claims"]
          if e["claim"] == "BARRIER_CORRESPONDENCE_PROVED"]
    assert len(wm) == 1


def test_a_racy_source_fails_the_whole_bundle_by_name(tmp_path):
    racy = WITNESS.replace("void smp_mb(void) {}\n", "") \
                  .replace("            smp_mb();\n", "")
    root = _kernel(tmp_path, ring=racy)
    # the racy source still detects as an SPSC ring for the witness lane
    bundle = verify_kernel(root, [_profile(tmp_path, N150, "n150")])
    assert bundle["status"] == "KERNEL_VERIFICATION_FAILED"
    assert bundle["failures"][0]["code"] == "WEAK_MEMORY_VIOLATION"
    assert bundle["failures"][0]["profile"] == "n150"
    assert bundle["failures"][0]["source"] == "ring.c"


def test_missing_deadline_and_map_fail_closed(tmp_path):
    root = _kernel(tmp_path)
    no_model = _profile(tmp_path, {"target": "t"}, "bare")
    assert verify_kernel(root, [no_model])["code"] == "profile_field_missing"
    no_timing = _profile(tmp_path, {"target": "t", "memory_model": "x86_tso"},
                         "notiming")
    assert verify_kernel(root, [no_timing])["code"] == "profile_field_missing"
    bad_model = _profile(
        tmp_path, {"target": "t", "memory_model": "rc11"}, "badmodel")
    assert verify_kernel(root, [bad_model])["code"] == "profile_field_missing"


def test_manifest_and_profile_residuals_fail_closed(tmp_path):
    assert verify_kernel(tmp_path / "nope",
                         [_profile(tmp_path, N150, "n150")])["code"] == \
        "kernel_dir_missing"
    empty = tmp_path / "empty"
    empty.mkdir()
    assert verify_kernel(empty, [_profile(tmp_path, N150, "n150")])["code"] \
        == "kernel_manifest_missing"
    root = _kernel(tmp_path)
    (root / "kernel.json").write_text("{not json", encoding="utf-8")
    assert verify_kernel(root, [_profile(tmp_path, N150, "n150")])["code"] \
        == "kernel_manifest_invalid"
    (root / "kernel.json").write_text("{}", encoding="utf-8")
    assert verify_kernel(root, [])["code"] == "profiles_missing"
    assert verify_kernel(
        root, [tmp_path / "ghost.json"])["code"] == "profile_unreadable"


def test_dma_map_can_live_in_the_profile_instead(tmp_path):
    """The physical map is per-architecture: a profile-level memory_map
    overrides the kernel-level default (that is the multi-arch point)."""
    root = _kernel(tmp_path)
    manifest = json.loads((root / "kernel.json").read_text())
    del manifest["memory_map"], manifest["dma_contracts"]
    (root / "kernel.json").write_text(json.dumps(manifest), encoding="utf-8")
    profile = dict(N150, memory_map=MEMORY_MAP, dma_contracts=CONTRACTS)
    bundle = verify_kernel(root, [_profile(tmp_path, profile, "n150")])
    assert ("DMA_ISOLATION_PROVED",
            "deterministic_range_disjointness_n150") in {
        (e["claim"], e["scope"]) for e in bundle["claims"]}
    # and without either, the lattice refuses rather than guessing
    bare = _profile(tmp_path, {"target": "t", "memory_model": "x86_tso",
                               "timing": {"max_cycles": 500}}, "nomap")
    assert verify_kernel(root, [bare])["code"] == "profile_field_missing"
