# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M36: lock-free concurrency — the ESBMC interleaving judge.

Probe-grounded (real ESBMC 8.4.0): a two-thread SPSC ring (the kfifo
shape) with plain shared ints and a single-word store per thread — the
linearization point — VERIFIES under all explored interleavings; an
unguarded overfill FAILS. C11 atomics are NOT modeled by this ESBMC
build (__c11_atomic_* have no bodies → nondeterministic values), so the
dialect is plain shared memory under the SC pthread model.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pipeline.lockfree import detect_spsc_ring, linearization_coverage, \
    verify_lockfree

RING = """#include <pthread.h>
#include <assert.h>
#define CAP 4
int buf[CAP];
int head = 0;
int tail = 0;

void *producer(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int h = head;
        if (h - tail < CAP) {
            buf[h % CAP] = i;
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

MPMC = """#include <pthread.h>
int buf[8];
int head = 0, tail = 0;
void *a(void *x) { head = head + 1; return 0; }
void *b(void *x) { head = head + 1; return 0; }
int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, a, 0);
    pthread_create(&t2, 0, b, 0);
    pthread_join(t1, 0); pthread_join(t2, 0);
    return 0;
}
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _esbmc_installed() -> bool:
    return shutil.which("esbmc") is not None


def test_detects_the_spsc_ring_shape():
    """Phase 1: the kfifo shape — array + head/tail + exactly two thread
    functions, each with ONE single-word store to its shared index (the
    linearization point). MPMC (two writers of the same index) refuses by
    name — the probed dialect is SPSC only."""
    ring = detect_spsc_ring(RING)
    assert ring["status"] == "DETECTED"
    assert ring["capacity"] == 4
    assert ring["shared_fields"] == ["head", "tail"]

    assert detect_spsc_ring(MPMC)["code"] == "mpmc_not_in_dialect"
    assert detect_spsc_ring("int main(void){return 0;}")["code"] == \
        "no_ring_structure"


def test_linearization_point_coverage_gate():
    """The structural gate: each concurrent operation has EXACTLY one
    designated atomic step where it takes effect — one single-word store
    to the shared index. Zero or multiple stores fail closed."""
    coverage = linearization_coverage(RING, detect_spsc_ring(RING))
    assert coverage["status"] == "COVERAGE_PROVED"
    assert coverage["linearization_points"] == {"producer": "head",
                                                "consumer": "tail"}

    two_stores = RING.replace("head = h + 1;",
                              "head = h + 1; head = head;")
    verdict = linearization_coverage(two_stores,
                                     detect_spsc_ring(two_stores))
    assert verdict["code"] == "LINEARIZATION_MULTIPLE_STORES"

    none = RING.replace("tail = t + 1;", "t = t + 1;")
    verdict = linearization_coverage(none, detect_spsc_ring(none))
    assert verdict["code"] == "LINEARIZATION_POINT_MISSING"


@pytest.mark.skipif(not _esbmc_installed(), reason="real esbmc not installed")
def test_real_esbmc_proves_all_interleavings(tmp_path):
    """The judge: real ESBMC explores the producer/consumer interleavings
    and the capacity invariant holds — LOCK_FREE_LINEARIZABILITY_PROVED
    with the fairness split recorded."""
    source = _write(tmp_path, "ring.c", RING)
    verdict = verify_lockfree(source)
    assert verdict["status"] == "LOCK_FREE_LINEARIZABILITY_PROVED", verdict
    assert verdict["claim"] == "LOCK_FREE_LINEARIZABILITY_PROVED"
    assert verdict["judge"] == "esbmc"
    assert verdict["scope"] == "concurrent_interleaving_bmc"
    assert verdict["concurrency_model"] == "lock_free_spsc"
    assert verdict["scheduler_fairness"] == "human_accepted_assumption"
    assert verdict["progress_proved"] is False


@pytest.mark.skipif(not _esbmc_installed(), reason="real esbmc not installed")
def test_real_esbmc_refuses_a_broken_ring(tmp_path):
    """The judge is not decorative: an unguarded producer overfills past
    CAP while the consumer never pops — the capacity invariant is violated
    and the verdict fails closed."""
    broken = (RING
              .replace("if (h - tail < CAP) {", "if (1) {")
              .replace("for (int i = 0; i < 3; i++) {\n        int h = head;",
                       "for (int i = 0; i < 6; i++) {\n        int h = head;")
              .replace("for (int i = 0; i < 3; i++) {\n        int t = tail;",
                       "for (int i = 0; i < 0; i++) {\n        int t = tail;"))
    assert "i < 6" in broken and "i < 0" in broken
    source = _write(tmp_path, "broken.c", broken)
    verdict = verify_lockfree(source)
    assert verdict["status"] == "LOCK_FREE_VERIFICATION_FAILED"
    assert verdict["code"] == "interleaving_violation"
    assert verdict["claim"] == "NO_PROOF"


def test_detection_edge_pins():
    """Unclosed braces, missing index, and gate passthroughs."""
    from pipeline.lockfree import detect_spsc_ring, linearization_coverage
    # head without tail: not the SPSC dialect
    head_only = ("#define CAP 4\nint buf[CAP];\nint head = 0;\n"
                 "void *p(void *x){head = 1; return 0;}\n"
                 "int main(void){pthread_t t; pthread_create(&t,0,p,0); "
                 "pthread_join(t,0); return 0;}")
    assert detect_spsc_ring(head_only)["code"] == "no_ring_structure"
    # a non-DETECTED detection passes through the coverage gate unchanged
    refused = linearization_coverage(head_only, detect_spsc_ring(head_only))
    assert refused["code"] == "no_ring_structure"
    # unclosed function body: the brace scan clamps at end-of-text
    unclosed = ("#define CAP 2\nint buf[2];\nint head = 0, tail = 0;\n"
                "void *p(void *x){head = 1; return 0;")
    assert detect_spsc_ring(unclosed)["status"] in {"DETECTED", "FAILED"} or \
        detect_spsc_ring(unclosed)["code"] == "no_ring_structure"
    # a shared index stored only in a thread fn that is never created:
    # coverage names the missing linearization point's owner
    never_created = ("#define CAP 2\nint buf[2];\nint head = 0, tail = 0;\n"
                     "void *ghost(void *x){head = 1; return 0;}\n"
                     "void *p(void *x){head = 1; return 0;}\n"
                     "int main(void){pthread_t t; pthread_create(&t,0,p,0);"
                     " pthread_join(t,0); return 0;}")
    detection = detect_spsc_ring(never_created)
    assert detection["status"] == "DETECTED", detection
    verdict = linearization_coverage(never_created, detection)
    assert verdict["code"] == "LINEARIZATION_POINT_MISSING"


def test_brace_clamp_fallbacks():
    """Unclosed bodies clamp at end-of-text in both scanners."""
    from pipeline.lockfree import _brace_matched_body
    from pipeline.weak_memory import _brace_matched_body as wm_body
    unclosed = "void *f(void *x){head = 1;"
    open_brace = unclosed.index("{")
    assert "head = 1;" in _brace_matched_body(unclosed, open_brace)
    assert "head = 1;" in wm_body(unclosed, open_brace)


def test_verify_passthroughs_and_no_verdict(tmp_path, monkeypatch):
    """The verify entry passes gate refusals through and reports an
    ESBMC run that yields no verdict (garbage output) by name."""
    from subprocess import CompletedProcess
    from unittest.mock import patch

    from pipeline.lockfree import verify_lockfree
    never_stores = ("#define CAP 2\nint buf[2];\nint head = 0, tail = 0;\n"
                     "int main(void){pthread_t t; pthread_create(&t,0,p,0);"
                     " pthread_join(t,0); return 0;}")
    passthrough = verify_lockfree(_write(tmp_path, "np.c", never_stores))
    assert passthrough["code"] == "LINEARIZATION_POINT_MISSING"

    with patch("subprocess.run", return_value=CompletedProcess(
            args=[], returncode=0, stdout="mysterious silence",
            stderr="")):
        verdict = verify_lockfree(_write(tmp_path, "ring.c", RING))
    assert verdict["code"] == "esbmc_no_verdict"


def test_residuals_fail_closed(tmp_path, monkeypatch):
    """Out-of-dialect sources, missing files, and prover residuals refuse
    by name. Hermetic: subprocess mocked (CI runners have no esbmc)."""
    from subprocess import CompletedProcess
    from unittest.mock import patch

    from pipeline import config
    assert verify_lockfree(tmp_path / "nope.c")["code"] == \
        "input_unavailable"
    rust = _write(tmp_path, "L.rs", "pub fn f() {}")
    assert verify_lockfree(rust)["code"] == "UNSUPPORTED_BOUNDARY"
    assert verify_lockfree(_write(tmp_path, "m.c", MPMC))["code"] == \
        "mpmc_not_in_dialect"
    no_threads = _write(tmp_path, "nt.c",
                        "#define CAP 4\nint buf[4]; int head=0, tail=0;")
    assert verify_lockfree(no_threads)["code"] == "no_thread_harness"

    monkeypatch.setattr("pipeline.lockfree.ESBMC_AVAILABLE", False)
    assert verify_lockfree(_write(tmp_path, "ring.c", RING))["code"] == \
        "esbmc_unavailable"
    monkeypatch.undo()

    with patch("subprocess.run",
               side_effect=TimeoutError("slow")):
        assert verify_lockfree(_write(tmp_path, "ring.c", RING))["code"] \
            == "esbmc_timeout"
    with patch("subprocess.run", return_value=CompletedProcess(
            args=[], returncode=0, stdout="",
            stderr="esbmc: compile error")):
        verdict = verify_lockfree(_write(tmp_path, "ring.c", RING))
        assert verdict["code"] in {"esbmc_crashed", "esbmc_parse_error"}
