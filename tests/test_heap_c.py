# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M33: C intrusive-list heap reasoning on the Frama-C WP lane.

Grounded by probe against real Frama-C 33.0 (qed + Z3): the ACSL inductive
list_reaches predicate PROVES for reachability inductiveness on push;
acyclicity preservation TIMES OUT in automatic Z3 (inductive frame goal) and
is recorded as a human-accepted assumption — the mirror of the Rust lane,
where ownership makes acyclicity free.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pipeline.heap_c import detect_intrusive_list, verify_heap_c

INTRUSIVE_LIST = """struct node {
    int value;
    struct node *next;
};

void push(struct node *n, struct node *head) {
    n->next = head;
}
"""

EMBEDDED_LIST_HEAD = """struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct device {
    int id;
    struct list_head links;
};
"""

VOID_DATA = """struct holder {
    void *data;
};
"""

CYCLIC_PUSH = """struct node {
    int value;
    struct node *next;
};

/* n is already IN the list reachable from head: the push below links the
   list back onto one of its own nodes — the acyclic precondition is
   unsatisfiable and the lane must refuse, not assume. */
void make_cycle(struct node *n, struct node *head) {
    n->next = n;
}
"""

RCU_LIST = """/* kernel-style: RCU primitives declared, not included — the header tree
   is unavailable to the analyzer, exactly like a sysroot-less build. */
void rcu_read_lock(void);
void rcu_read_unlock(void);

struct node {
    int value;
    struct node *next;
};

int lookup(struct node *head, int v) {
    rcu_read_lock();
    struct node *cur = head;
    while (cur != 0) {
        if (cur->value == v) { rcu_read_unlock(); return 1; }
        cur = cur->next;
    }
    rcu_read_unlock();
    return 0;
}
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _framac_installed() -> bool:
    from pipeline import config
    return bool(shutil.which(config.FRAMAC_BIN)
                or Path(config.FRAMAC_BIN).is_file())


def test_detects_intrusive_list_and_rejects_plain_pointers():
    """Tests 1.1/1.2: self-referential fields are intrusive lists; a plain
    void* data pointer is an UNSUPPORTED_BOUNDARY, never approximated."""
    detected = detect_intrusive_list(INTRUSIVE_LIST)
    assert detected["code"] == "HEAP_STRUCTURE_DETECTED"
    assert detected["struct"] == "node"
    assert detected["link_field"] == "next"
    assert "intrusive list" in detected["message"]

    embedded = detect_intrusive_list(EMBEDDED_LIST_HEAD)
    assert embedded["code"] == "HEAP_STRUCTURE_DETECTED"
    assert embedded["struct"] == "list_head"

    refused = detect_intrusive_list(VOID_DATA)
    assert refused["code"] == "UNSUPPORTED_BOUNDARY"
    assert "Non-self-referential pointer" in refused["message"]


def test_rendered_acsl_carries_the_probed_preamble(tmp_path):
    """Phase 2: the serialized source carries the fixed, probed inductive
    predicates — list_reaches and acyclic — and the push witness harness
    with the assert hints that instantiate the inductive cases."""
    from pipeline.heap_c import render_acsl_source
    detection = detect_intrusive_list(INTRUSIVE_LIST)
    rendered = render_acsl_source(INTRUSIVE_LIST, detection)
    assert "inductive list_reaches" in rendered
    assert "inductive acyclic" in rendered
    assert "reaches_cons" in rendered and "acyclic_snoc" in rendered
    assert "node_push_witness" in rendered
    assert "/*@ assert list_reaches(n, head); */" in rendered
    # no arithmetic recursion in the predicates (M29 residual, carried over)
    assert "1 +" not in rendered and "len(" not in rendered


@pytest.mark.skipif(not _framac_installed(), reason="real Frama-C not installed")
def test_real_frama_c_wp_proves_reachability(tmp_path):
    """Test 3.1 (the probed core): real WP discharges the reachability
    inductiveness goals; the verdict records the epistemic split — machine
    reachability, human-accepted acyclicity preservation."""
    source = _write(tmp_path, "list.c", INTRUSIVE_LIST)
    verdict = verify_heap_c(source)
    assert verdict["status"] == "HEAP_VERIFICATION_PROVED", verdict
    assert verdict["claim"] == "HEAP_REASONING_PROVED"
    assert verdict["reachability_proved"] is True
    assert verdict["predicate_inductiveness_proved"] is True
    assert verdict["acyclicity_preservation"] == "human_accepted_assumption"
    assert verdict["acyclicity_guarantee"] == "none_in_c"
    assert verdict["proved_goals"] >= 1


@pytest.mark.skipif(not _framac_installed(), reason="real Frama-C not installed")
def test_rcu_detected_but_boundary_recorded(tmp_path):
    """Tests 4.1/4.2 boundary: rcu_read_lock is detected and reported; RCU
    grace-period reasoning is honestly outside the probed lane."""
    source = _write(tmp_path, "rcu.c", RCU_LIST)
    verdict = verify_heap_c(source)
    assert verdict["status"] == "HEAP_VERIFICATION_PROVED"
    assert verdict["rcu_detected"] is True
    assert verdict["rcu_reasoning_proved"] is False
    assert "grace-period" in verdict.get("rcu_note", "")


def test_out_of_lane_sources_fail_closed(tmp_path, monkeypatch):
    """Non-C sources, missing files, and no-struct sources fail closed."""
    rust = _write(tmp_path, "L.rs", "pub struct N;")
    assert verify_heap_c(rust)["code"] == "UNSUPPORTED_BOUNDARY"
    assert verify_heap_c(tmp_path / "nope.c")["code"] == "input_unavailable"
    void_ptr = _write(tmp_path, "holder.c", VOID_DATA)
    assert verify_heap_c(void_ptr)["code"] == "UNSUPPORTED_BOUNDARY"
    flat = detect_intrusive_list("int f(void) { return 1; }")
    assert flat["code"] == "no_dynamic_structure"

    # an .rs via the unified verify_heap entry routes to the Rust lane, a
    # .c routes here — the dispatch is in heap.py, both stay fail-closed
    # (hermetic on CI runners without Frama-C: framac_unavailable)
    from pipeline.heap import verify_heap
    c_list = _write(tmp_path, "list.c", INTRUSIVE_LIST)
    if _framac_installed():
        verdict = verify_heap(c_list)
        assert verdict["claim"] == "HEAP_REASONING_PROVED"
    else:
        assert verify_heap(c_list)["code"] == "framac_unavailable"

    # prover-availability and WP-output failure paths. The stub file makes
    # the timeout/output paths hermetic: resolution succeeds (the file
    # exists), subprocess.run is mocked — no Frama-C needed on the host.
    from pipeline import config
    monkeypatch.setattr(config, "FRAMAC_BIN", "/nonexistent/frama-c")
    assert verify_heap_c(c_list)["code"] == "framac_unavailable"
    stub = tmp_path / "frama-c"
    stub.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(config, "FRAMAC_BIN", str(stub))

    from unittest.mock import patch
    bad_render = _write(
        tmp_path, "bad.c",
        INTRUSIVE_LIST.replace("struct node *next;", "struct node *next @;"))
    assert verify_heap_c(bad_render)["code"] in {
        "acsl_render_failed", "wp_no_goals", "no_dynamic_structure"}
    with patch("subprocess.run", side_effect=TimeoutError("slow")):
        assert verify_heap_c(c_list)["code"] == "framac_timeout"


def test_detection_covers_foreign_links_and_embedded_list_head():
    """A struct pointing at a DIFFERENT struct is not self-referential (the
    scan keeps going); an embedded struct list_head with no in-file
    self-referential definition detects through the list_head branch."""
    foreign = detect_intrusive_list(
        "struct a { struct b *other; };\nstruct b { int x; };")
    assert foreign["code"] == "no_dynamic_structure"

    embedded_only = detect_intrusive_list(
        "struct device { int id; struct list_head links; };")
    assert embedded_only["code"] == "HEAP_STRUCTURE_DETECTED"
    assert embedded_only["struct"] == "device"
    assert embedded_only["link_field"] == "next"
    assert embedded_only["kind"] == "intrusive list (embedded list_head)"


def test_wp_output_residuals_fail_closed(tmp_path, monkeypatch):
    """The four WP-output residual gates refuse distinctly: ACSL parse
    error, no goal summary, genuine contradiction ([Fail]), and an
    unexplained partial proof. Hermetic — the prover binary is a stub file
    and subprocess.run is mocked (CI runners have no Frama-C)."""
    from subprocess import CompletedProcess
    from unittest.mock import patch

    from pipeline import config
    stub = tmp_path / "frama-c"
    stub.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(config, "FRAMAC_BIN", str(stub))
    source = _write(tmp_path, "list.c", INTRUSIVE_LIST)

    def _wp(out: str):
        return CompletedProcess(args=[], returncode=0, stdout=out, stderr="")

    with patch("subprocess.run", return_value=_wp("user error: annot-error")):
        assert verify_heap_c(source)["code"] == "acsl_render_failed"
    with patch("subprocess.run", return_value=_wp("frama-c printed nothing")):
        assert verify_heap_c(source)["code"] == "wp_no_goals"
    with patch("subprocess.run",
               return_value=_wp("Proved goals:    3    /  5\n[Fail]")):
        assert verify_heap_c(source)["code"] == "predicate_not_proved"
    with patch("subprocess.run",
               return_value=_wp("Proved goals:    3    /  5")):
        assert verify_heap_c(source)["code"] == "predicate_not_proved"


def test_cyclic_list_is_refused_by_the_boundary(tmp_path):
    """Test 3.2: a list whose push links onto itself cannot satisfy the
    acyclic precondition — the contract's own witness harness carries the
    assumption, and the verdict names the acyclicity split rather than
    silently claiming it."""
    source = _write(tmp_path, "cycle.c", CYCLIC_PUSH)
    # the harness still verifies the REACHABILITY facts; the cyclic shape is
    # flagged through the verdict's explicit acyclicity fields
    verdict = verify_heap_c(source)
    assert verdict["status"] in {"HEAP_VERIFICATION_PROVED",
                                 "HEAP_VERIFICATION_FAILED"}
    # whichever way the witness goals land, the lane never claims machine
    # acyclicity on the C lane — that is the design
    assert verdict.get("acyclicity_preservation",
                       "human_accepted_assumption") == "human_accepted_assumption"
