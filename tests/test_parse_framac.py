# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from pipeline.parse_framac import parse_framac_vcs


def test_parse_failed_framac_goals_into_shared_vcs():
    text = """[wp] Failed: Postcondition in function increment candidate.c:7
[wp] [rte] Unknown: signed overflow candidate.c:9
[wp] Proved: another goal
"""
    vcs = parse_framac_vcs(text)
    assert [(vc.category, vc.line) for vc in vcs] == [
        ("Postcondition", 7), ("ArithmeticOperationRange", 9)]
    assert vcs[0].method == "increment"


def test_parse_framac_deduplicates_and_categorizes_reviewed_shapes():
    rows = [
        "[wp] Failed: pointer valid",
        "[wp] Failed: pointer valid",
        "[wp] Unknown: array bounds",
        "[wp] Timeout: assigns clause",
        "[wp] Failed: loop invariant",
        "[wp] Failed: termination",
        "[wp] Failed: unexplained goal",
    ]
    vcs = parse_framac_vcs("\n".join(rows))
    assert [item.category for item in vcs] == [
        "PointerValidity", "ArrayAccess", "FrameCondition", "LoopInvariant",
        "Termination", "FramaCVerification"]
    assert all(item.line == 0 and item.file == "candidate.c" for item in vcs)
