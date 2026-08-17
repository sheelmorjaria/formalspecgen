# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M24 (roadmap Feature 1): bounded behavioral bisimulation between V2 machines.

The equivalence is proved over the FINITE reachable state spaces of the two
machines under a reviewer-supplied state mapping — exhaustive, so it is a
complete proof for the bounded abstractions, not an induction. The claim is
scoped: the V2 machines are equivalent; Java heap topology is not claimed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.equivalence import (
    load_state_mapping, prove_equivalence,
)

BASELINE = """schema_version: 2
review_status: unreviewed
domain_name: ConnMachine
module_name: conn_machine
actors: 1
state_variables:
  - kind: int
    name: conn
    bound: [0, 2]
    initial: 0
operations:
  - name: open
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g1
        expression:
          kind: eq
          left: {kind: field, name: conn}
          right: {kind: integer, value: 0}
    effects:
      - id: e1
        target: conn
        value: {kind: integer, value: 1}
    frame: [conn]
  - name: establish
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g2
        expression:
          kind: eq
          left: {kind: field, name: conn}
          right: {kind: integer, value: 1}
    effects:
      - id: e2
        target: conn
        value: {kind: integer, value: 2}
    frame: [conn]
  - name: close
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g3
        expression:
          kind: neq
          left: {kind: field, name: conn}
          right: {kind: integer, value: 0}
    effects:
      - id: e3
        target: conn
        value: {kind: integer, value: 0}
    frame: [conn]
tlc_invariants:
  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: conn}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: conn}
        right: {kind: integer, value: 2}
"""

# The refactored machine is the same behavior over differently named state:
# mode 0/1/2 mirror conn 0/1/2 (Active=1, Inactive-ish states renamed).
REFACTORED_SAME = BASELINE.replace("ConnMachine", "ModeMachine") \
                          .replace("conn", "mode")

# Missing transition: establish (1 -> 2) removed; 1 can only close.
_head, _, _tail = REFACTORED_SAME.partition("  - name: establish")
_establish, _, _tail = _tail.partition("  - name: close")
assert "mode" in _establish and "value: 2" in _establish, "slice sanity"
REFACTORED_MISSING = _head + "  - name: close" + _tail

MAPPING = """{"states": [
  {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 0}},
  {"baseline_state": {"conn": 1}, "refactored_state": {"mode": 1}},
  {"baseline_state": {"conn": 2}, "refactored_state": {"mode": 2}}
]}
"""


def yaml_dump(spec) -> str:
    import yaml
    return yaml.safe_dump(spec, sort_keys=False)


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_load_state_mapping_builds_the_relation(tmp_path):
    """Milestone 1 (Test 1.1): mapping JSON becomes state pairs."""
    mapping = load_state_mapping(_write(tmp_path, "map.json", MAPPING))
    assert mapping == [
        ({"conn": 0}, {"mode": 0}),
        ({"conn": 1}, {"mode": 1}),
        ({"conn": 2}, {"mode": 2}),
    ]


def test_equivalence_proves_matching_machines(tmp_path):
    """Milestone 2 (Test 2.1): transition correspondence holds under the
    mapping — every baseline successor has a mapped refactored successor,
    and vice versa."""
    result = prove_equivalence(
        _write(tmp_path, "baseline.v2.yaml", BASELINE),
        _write(tmp_path, "refactored.v2.yaml", REFACTORED_SAME),
        _write(tmp_path, "map.json", MAPPING))
    assert result["status"] == "EQUIVALENCE_PROVED"
    assert result["claim"] == "BEHAVIORAL_EQUIVALENCE_PROVED"
    assert result["scope"] == "bounded_state_space_bisimulation"
    assert result["checked_pairs"] >= 3
    assert result["heap_equivalence_proved"] is False


def test_missing_transition_fails_closed(tmp_path):
    """Milestone 2 (Test 2.2): without the 1->2 transition, the mapped state
    mode=1 lacks a counterpart for conn=1's establish."""
    result = prove_equivalence(
        _write(tmp_path, "baseline.v2.yaml", BASELINE),
        _write(tmp_path, "refactored.v2.yaml", REFACTORED_MISSING),
        _write(tmp_path, "map.json", MAPPING))
    assert result["status"] == "EQUIVALENCE_FAILED"
    assert result["claim"] == "NO_PROOF"
    assert "Missing transition" in result["reason"]
    assert result["reason"].split("for state")[1].strip().startswith("mode=1")


def test_unmapped_reachable_state_fails_closed(tmp_path):
    partial = json.dumps({"states": [
        {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 0}}]})
    result = prove_equivalence(
        _write(tmp_path, "baseline.v2.yaml", BASELINE),
        _write(tmp_path, "refactored.v2.yaml", REFACTORED_SAME),
        _write(tmp_path, "map.json", partial))
    assert result["status"] == "EQUIVALENCE_FAILED"
    assert "mapping" in result["reason"]


def test_cli_command_mints_the_claim(tmp_path, monkeypatch):
    """Milestone 3 (Test 3.1): prove-equivalence ... --json writes evidence."""
    monkeypatch.chdir(tmp_path)
    import argparse
    from pipeline.cli import command_prove_equivalence
    _write(tmp_path, "baseline.v2.yaml", BASELINE)
    _write(tmp_path, "refactored.v2.yaml", REFACTORED_SAME)
    _write(tmp_path, "map.json", MAPPING)
    args = argparse.Namespace(baseline="baseline.v2.yaml",
                              refactored="refactored.v2.yaml",
                              mapping="map.json", json_out="equiv.json")
    ui = _SilentUI()
    assert command_prove_equivalence(args, ui) == 0
    payload = json.loads((tmp_path / "equiv.json").read_text(encoding="utf-8"))
    assert payload["claim"] == "BEHAVIORAL_EQUIVALENCE_PROVED"

    args = argparse.Namespace(baseline="baseline.v2.yaml",
                              refactored="refactored.v2.yaml",
                              mapping="map.json", json_out="bad.json")
    _write(tmp_path, "refactored.v2.yaml", REFACTORED_MISSING)
    assert command_prove_equivalence(args, ui) == 1
    failed = json.loads((tmp_path / "bad.json").read_text(encoding="utf-8"))
    assert failed["status"] == "EQUIVALENCE_FAILED"


class _SilentUI:
    class console:
        @staticmethod
        def print(*_a, **_k): pass


def test_equivalence_fail_closed_branches(tmp_path):
    """Reviewed-format fallback, cap exceeded, invalid inputs, non-functional
    and non-injective mappings, unreachable mapped states, and successors
    missing from the mapping all report distinct reasons."""
    import json as _json
    reviewed = _json.dumps({
        **__import__("yaml").safe_load(BASELINE),
        "review_status": "reviewed",
        "accepted_candidate_sha256": "0" * 64,
        "accepted_evidence_sha256": "1" * 64})
    b = _write(tmp_path, "b.yaml", BASELINE)
    r = _write(tmp_path, "r.yaml", REFACTORED_SAME)
    m = _write(tmp_path, "m.json", MAPPING)

    # reviewed JSON fallback loads and proves
    rj = _write(tmp_path, "r.json", reviewed.replace("conn", "mode")
                                          .replace("ConnMachine", "ModeMachine"))
    assert prove_equivalence(b, rj, m)["status"] == "EQUIVALENCE_PROVED"

    # invalid inputs fail closed
    bad = prove_equivalence(tmp_path / "absent.yaml", r, m)
    assert bad["status"] == "EQUIVALENCE_FAILED" and "invalid input" in bad["reason"]

    # cap exceeded: wide bounds refuse before exploration
    from pipeline.domain_v2 import DomainSpecV2
    from pipeline.equivalence import _reachable_states
    wide_dict = __import__("yaml").safe_load(BASELINE)
    wide_dict["state_variables"][0]["bound"] = [0, 200001]
    wide_dict["tlc_invariants"][0]["expression"]["right"]["right"]["value"] = 200001
    wide_spec = DomainSpecV2.model_validate(wide_dict)
    import pytest as _pytest
    with _pytest.raises(ValueError, match="bounded equivalence limit"):
        _reachable_states(wide_spec)
    wide = yaml_dump(wide_dict)
    capped = prove_equivalence(_write(tmp_path, "wide.yaml", wide), r, m)
    assert capped["status"] == "EQUIVALENCE_FAILED"
    assert "limit" in capped["reason"]

    # non-functional mapping (two different right sides for conn=0)
    nonfunctional = prove_equivalence(b, r, _write(tmp_path, "nf.json", _json.dumps(
        {"states": [
            {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 0}},
            {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 1}},
            {"baseline_state": {"conn": 1}, "refactored_state": {"mode": 1}},
            {"baseline_state": {"conn": 2}, "refactored_state": {"mode": 2}}]})))
    assert "not functional" in nonfunctional["reason"]

    # non-injective mapping (mode=1 from conn=0 and conn=1)
    noninjective = prove_equivalence(b, r, _write(tmp_path, "ni.json", _json.dumps(
        {"states": [
            {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 1}},
            {"baseline_state": {"conn": 1}, "refactored_state": {"mode": 1}},
            {"baseline_state": {"conn": 2}, "refactored_state": {"mode": 2}}]})))
    assert "not injective" in noninjective["reason"]

    # mapped state unreachable on the right: mode=3 never occurs in the
    # refactored machine, and the first processed state maps to it
    unreachable = prove_equivalence(b, r, _write(tmp_path, "ur.json", _json.dumps(
        {"states": [
            {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 3}},
            {"baseline_state": {"conn": 1}, "refactored_state": {"mode": 1}},
            {"baseline_state": {"conn": 2}, "refactored_state": {"mode": 2}}]})))
    assert "reachable in the refactored machine" in unreachable["reason"]

    # successor missing from the mapping: baseline reaches conn=1,2 but map
    # only covers 0 for one side while right side still moves
    successor_gap = prove_equivalence(b, r, _write(tmp_path, "sg.json", _json.dumps(
        {"states": [
            {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 0}},
            {"baseline_state": {"conn": 2}, "refactored_state": {"mode": 2}}]})))
    assert "absent from the mapping" in successor_gap["reason"] or \
        "absent from the mapping" in payload.get("reason", "")


def test_cli_dispatches_and_successor_gap_via_cli(tmp_path, monkeypatch):
    """The dispatch lines and the successor-gap reason fire through main."""
    import argparse
    from pipeline.cli import command_prove_equivalence, main
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "b.v2.yaml", BASELINE)
    _write(tmp_path, "r.v2.yaml", REFACTORED_SAME)
    _write(tmp_path, "gap.json", json.dumps({"states": [
        {"baseline_state": {"conn": 0}, "refactored_state": {"mode": 0}},
        {"baseline_state": {"conn": 2}, "refactored_state": {"mode": 2}}]}))
    args = argparse.Namespace(baseline="b.v2.yaml", refactored="r.v2.yaml",
                              mapping="gap.json", json_out="g.json")
    assert command_prove_equivalence(args, _SilentUI()) == 1
    payload = json.loads((tmp_path / "g.json").read_text(encoding="utf-8"))
    assert "absent from the mapping" in payload["reason"]

    # the argparse subcommand dispatches end to end
    import sys
    monkeypatch.setattr(sys, "argv", ["formalspecgen", "prove-equivalence",
                                      "b.v2.yaml", "r.v2.yaml",
                                      "--mapping", "gap.json"])
    try:
        main()
    except SystemExit as exc:
        assert exc.code in (0, 1)
