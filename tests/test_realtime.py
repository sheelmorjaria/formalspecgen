# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M38: real-time — deterministic WCET bound + bounded liveness."""
from __future__ import annotations

from pathlib import Path

from pipeline.realtime import liveness_check, wcet_bound

ISR = """int handle(int irq) {
    int status = irq & 3;
    for (int i = 0; i < 8; i++) {
        status = status + 1;
    }
    return status;
}
"""

UNBOUNDED_LOOP = """int poll(void) {
    while (ready == 0) { }
    return ready;
}
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_wcet_bound_proves_within_deadline(tmp_path):
    verdict = wcet_bound(_write(tmp_path, "isr.c", ISR),
                         {"max_cycles": 500})
    assert verdict["status"] == "WCET_BOUND_PROVEN"
    assert verdict["claim"] == "WCET_BOUND_PROVEN"
    assert verdict["wcet_cycles"] <= 500
    assert verdict["headroom_cycles"] >= 0
    assert verdict["cost_model_ownership"] == \
        "human_declared_hardware_profile"
    assert "judge_pending" in verdict["wcet_method"]


def test_deadline_missed_and_unbounded_fail_closed(tmp_path):
    tight = wcet_bound(_write(tmp_path, "isr.c", ISR),
                       {"max_cycles": 5})
    assert tight["status"] == "DEADLINE_MISSED"
    assert tight["code"] == "DEADLINE_MISSED"
    assert tight["claim"] == "NO_PROOF"

    unbounded = wcet_bound(_write(tmp_path, "poll.c", UNBOUNDED_LOOP),
                           {"max_cycles": 100})
    assert unbounded["code"] == "UNBOUNDED_LOOP_DETECTED"
    assert "never guesses" in unbounded["message"]

    declared = wcet_bound(_write(tmp_path, "poll.c", UNBOUNDED_LOOP),
                          {"max_cycles": 100,
                           "loop_bounds": {"ready": 1}})
    assert declared["status"] == "WCET_BOUND_PROVEN"

    assert wcet_bound(tmp_path / "nope.c",
                      {"max_cycles": 10})["code"] == "input_unavailable"
    assert wcet_bound(_write(tmp_path, "L.rs", "fn f(){}"),
                      {"max_cycles": 10})["code"] == "UNSUPPORTED_BOUNDARY"
    assert wcet_bound(_write(tmp_path, "x.c", "int f(void){return 0;}"),
                      {})["code"] == "timing_constraints_missing"


def test_liveness_proved_and_starvation_refused():
    domain = {"transitions": [
        {"from": {"state": "READY"}, "to": {"state": "BUSY"}},
        {"from": {"state": "BUSY"}, "to": {"state": "READY"}},
    ], "ready_state": {"state": "READY"}}
    verdict = liveness_check(domain)
    assert verdict["status"] == "LIVENESS_PROVED"
    assert verdict["claim"] == "LIVENESS_PROVED"
    assert verdict["scheduler_fairness"] == "human_accepted_assumption"

    starving = {"transitions": [
        {"from": {"state": "READY"}, "to": {"state": "STUCK"}},
    ], "ready_state": {"state": "READY"}}
    refused = liveness_check(starving)
    assert refused["code"] == "LIVENESS_VIOLATION"
    assert refused["claim"] == "NO_PROOF"
    assert "STUCK" in refused["message"]

    assert liveness_check({"transitions": []})["code"] == "no_transitions"
