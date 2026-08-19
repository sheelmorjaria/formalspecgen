# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M37: weak-memory barrier correspondence (OS lane 2).

No weak-memory judge (herd7/RC11) is installed on this host, so this
lane mints ONLY the deterministic structural claim: every cross-thread
shared access is protected by an explicit ordering primitive. The full
WEAK_MEMORY_SAFETY_PROVED claim is recorded as unmintable until a
weak-memory judge is provisioned — never guessed.
"""
from __future__ import annotations

from pathlib import Path

from pipeline.weak_memory import MEMORY_MODELS, barrier_correspondence

BARRIERED = """#include <pthread.h>
int ready = 0;
int data = 0;

void *producer(void *arg) {
    (void)arg;
    data = 42;
    smp_mb();
    ready = 1;
    return 0;
}

void *consumer(void *arg) {
    (void)arg;
    while (!ready) { }
    smp_rmb();
    int v = data;
    (void)v;
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

RACY = """#include <pthread.h>
int ready = 0;
int data = 0;

void *producer(void *arg) {
    (void)arg;
    data = 42;
    ready = 1;      /* cross-thread store, NO ordering primitive */
    return 0;
}

void *consumer(void *arg) {
    (void)arg;
    while (!ready) { }
    int v = data;   /* cross-thread load, NO ordering primitive */
    (void)v;
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

ATOMIC = """#include <pthread.h>
_Atomic int ready = 0;
int data = 0;

void *producer(void *arg) {
    (void)arg;
    data = 42;
    atomic_store_explicit(&ready, 1, memory_order_release);
    return 0;
}

void *consumer(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&ready, memory_order_acquire)) { }
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


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_memory_model_profiles_are_the_closed_set():
    assert set(MEMORY_MODELS) == {"x86_tso", "armv8_sc"}
    assert MEMORY_MODELS["x86_tso"]["store_buffer"] is True
    assert MEMORY_MODELS["armv8_sc"]["store_buffer"] is False


def test_barrier_correspondence_proves_the_disciplined_source(tmp_path):
    """Every cross-thread access is bracketed by an ordering primitive →
    BARRIER_CORRESPONDENCE_PROVED (deterministic structural scope); the
    full weak-memory claim is honestly judge-pending."""
    verdict = barrier_correspondence(_write(tmp_path, "b.c", BARRIERED),
                                     "x86_tso")
    assert verdict["status"] == "BARRIER_CORRESPONDENCE_PROVED"
    assert verdict["claim"] == "BARRIER_CORRESPONDENCE_PROVED"
    assert verdict["memory_model"] == "x86_tso"
    assert verdict["scope"] == "deterministic_structural"
    assert verdict["cross_thread_fields"] == ["data", "ready"]
    assert verdict["weak_memory_safety"] == "unmintable_judge_pending"
    assert verdict["judge_pending"] == "herd7_or_rc11"

    atomic = barrier_correspondence(_write(tmp_path, "a.c", ATOMIC),
                                    "armv8_sc")
    assert atomic["status"] == "BARRIER_CORRESPONDENCE_PROVED"
    assert atomic["memory_model"] == "armv8_sc"


def test_racy_access_fails_closed_weak_memory_violation(tmp_path):
    """A cross-thread store with no ordering primitive is WEAK_MEMORY_
    VIOLATION — named field, named function, never approximated."""
    verdict = barrier_correspondence(_write(tmp_path, "r.c", RACY),
                                     "x86_tso")
    assert verdict["status"] == "WEAK_MEMORY_VERIFICATION_FAILED"
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["code"] == "WEAK_MEMORY_VIOLATION"
    joined = " ".join(verdict["violations"])
    assert "ready" in joined and "data" in joined
    assert "producer" in joined and "consumer" in joined


def test_residuals_fail_closed(tmp_path):
    assert barrier_correspondence(tmp_path / "nope.c", "x86_tso")["code"] \
        == "input_unavailable"
    assert barrier_correspondence(
        _write(tmp_path, "L.rs", "pub fn f() {}"), "x86_tso")["code"] == \
        "UNSUPPORTED_BOUNDARY"
    assert barrier_correspondence(
        _write(tmp_path, "b.c", BARRIERED), "rc11")["code"] == \
        "unknown_memory_model"
    single = _write(tmp_path, "s.c",
                    "#include <pthread.h>\nvoid *f(void *x){return 0;}\n"
                    "int main(void){return 0;}\n")
    assert barrier_correspondence(single, "x86_tso")["code"] == \
        "no_cross_thread_state"
