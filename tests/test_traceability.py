# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M23 (roadmap Feature 2): requirements -> invariant -> code traceability.

The matrix is deterministic evidence plumbing, never a proof claim: NL
requirements are matched to V2 invariants by field and bound, and to source
lines by field/bound occurrence. Unmatched requirements are reported, never
silently dropped.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline.traceability import (
    generate_traceability_matrix, parse_requirements,
)

REQUIREMENTS = """REQ-001: The counter must not exceed 5.
REQ-002: The system shall support at least 0 pending requests.
REQ-003: Pending requests must not exceed 100.
REQ-004: The latch must remain sealed indefinitely.
"""

# REQ-004 deliberately has no matching invariant (no numeric bound on any
# field it names): it must surface as UNMAPPED.


DOMAIN_YAML = """schema_version: 2
review_status: unreviewed
domain_name: BoundedCounter
module_name: bounded_counter
actors: 1
state_variables:
  - kind: int
    name: count
    bound: [0, 5]
    initial: 0
  - kind: int
    name: pending
    bound: [0, 100]
    initial: 0
operations:
  - name: increment
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g1
        expression:
          kind: lt
          left: {kind: field, name: count}
          right: {kind: integer, value: 5}
    effects:
      - id: e1
        target: count
        value:
          kind: add
          left: {kind: field, name: count}
          right: {kind: integer, value: 1}
    frame: [count]
tlc_invariants:
  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: count}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: count}
        right: {kind: integer, value: 5}
  - id: inv2
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: pending}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: pending}
        right: {kind: integer, value: 100}
"""

SOURCE = """public class Counter {
    private int count = 0;                 // line 2

    public void increment() {
        if (count < 5) { count = count + 1; }   // line 5: the REQ-001 guard
    }
}
"""


def test_parse_requirements_extracts_ids_and_text(tmp_path):
    """Milestone 1 (Test 1.1): .req lines become (id, text) pairs."""
    reqs = tmp_path / "requirements.req"
    reqs.write_text(REQUIREMENTS, encoding="utf-8")
    parsed = parse_requirements(reqs)
    assert [item["id"] for item in parsed] == \
        ["REQ-001", "REQ-002", "REQ-003", "REQ-004"]
    assert parsed[0]["text"] == "The counter must not exceed 5."
    assert parsed[1]["text"].startswith("The system shall support")


def test_matrix_maps_requirement_to_invariant_and_code_line(tmp_path):
    """Milestone 2 (Test 2.1): REQ-001 -> count <= 5 -> the guard line."""
    reqs = tmp_path / "requirements.req"
    reqs.write_text(REQUIREMENTS, encoding="utf-8")
    domain = tmp_path / "bounded_counter.v2.yaml"
    domain.write_text(DOMAIN_YAML, encoding="utf-8")
    source = tmp_path / "Counter.java"
    source.write_text(SOURCE, encoding="utf-8")

    matrix = generate_traceability_matrix(domain, source, reqs)
    rows = {row["req"]: row for row in matrix["rows"]}
    req1 = rows["REQ-001"]
    assert "count" in req1["invariant"] and "5" in req1["invariant"]
    assert req1["code_line"] == 5                     # the `count < 5` guard
    assert req1["source"] == "Counter.java"
    # REQ-002's lower bound maps to the pending invariant
    assert "pending" in rows["REQ-002"]["invariant"]
    # REQ-004 names no field with a matching bound: honestly unmapped
    assert rows["REQ-004"]["invariant"] is None
    assert matrix["coverage"] == {"mapped": 3, "total": 4}


def test_cli_command_writes_markdown_matrix(tmp_path, monkeypatch):
    """Milestone 3 (Test 3.1): the command emits a Markdown table."""
    monkeypatch.chdir(tmp_path)
    reqs = tmp_path / "requirements.req"
    reqs.write_text(REQUIREMENTS, encoding="utf-8")
    domain = tmp_path / "bounded_counter.v2.yaml"
    domain.write_text(DOMAIN_YAML, encoding="utf-8")
    source = tmp_path / "Counter.java"
    source.write_text(SOURCE, encoding="utf-8")

    import argparse
    from pipeline.cli import command_generate_traceability
    ui = _SilentUI()
    args = argparse.Namespace(domain=str(domain), source=str(source),
                              requirements=str(reqs),
                              out=str(tmp_path / "matrix.md"),
                              json_out=None)
    code = command_generate_traceability(args, ui)
    assert code == 0
    markdown = (tmp_path / "matrix.md").read_text(encoding="utf-8")
    assert markdown.startswith("# Traceability Matrix")
    assert "| REQ-001 |" in markdown and "count" in markdown
    assert "REQ-004" in markdown and "UNMAPPED" in markdown
    # the json side-car carries the structured rows
    payload = json.loads((tmp_path / "matrix.md").with_suffix(".json")
                         .read_text(encoding="utf-8"))
    assert payload["status"] == "TRACEABILITY_GENERATED"
    assert payload["coverage"]["total"] == 4


class _SilentUI:
    class console:
        @staticmethod
        def print(*_a, **_k): pass


def test_matrix_extras_directories_reviewed_format_and_edge_nodes(tmp_path):
    """Directory sources, the reviewed-artifact loader path, not/old
    rendering, and unreadable files all behave."""
    import json as _json
    (tmp_path / "sources").mkdir()
    (tmp_path / "sources" / "Counter.java").write_text(SOURCE, encoding="utf-8")
    (tmp_path / "sources" / "broken.java").write_bytes(b"\xff\xfe\x00bad")
    reqs = tmp_path / "requirements.req"
    reqs.write_text(REQUIREMENTS, encoding="utf-8")

    # a reviewed artifact (publication metadata) loads via the fallback
    import yaml
    candidate = tmp_path / "bounded_counter.v2.yaml"
    candidate.write_text(DOMAIN_YAML, encoding="utf-8")
    reviewed = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    reviewed["review_status"] = "reviewed"
    reviewed["accepted_candidate_sha256"] = "0" * 64
    reviewed["accepted_evidence_sha256"] = "1" * 64
    reviewed_path = tmp_path / "reviewed.json"
    reviewed_path.write_text(_json.dumps(reviewed), encoding="utf-8")

    matrix = generate_traceability_matrix(reviewed_path, tmp_path / "sources", reqs)
    rows = {row["req"]: row for row in matrix["rows"]}
    assert rows["REQ-001"]["source"] == "Counter.java"
    assert matrix["coverage"]["mapped"] == 3

    # not/old render and absent paths fail soft
    from pipeline.traceability import _expression_text, _source_files
    text = _expression_text({"kind": "not", "expression": {
        "kind": "old", "expression": {
            "kind": "eq", "left": {"kind": "field", "name": "count"},
            "right": {"kind": "integer", "value": 3}}}})
    assert text == "!(old(count == 3))"
    assert _source_files(tmp_path / "absent") == []


def test_bound_mismatch_and_list_walk(tmp_path):
    """A requirement naming a field with a bound no invariant carries is
    honestly unmapped (the invariant-skip branch), and _walk descends
    through list children."""
    from pipeline.traceability import _walk
    reqs = tmp_path / "requirements.req"
    reqs.write_text("REQ-001: count must not exceed 999.\n", encoding="utf-8")
    domain = tmp_path / "bounded_counter.v2.yaml"
    domain.write_text(DOMAIN_YAML, encoding="utf-8")
    source = tmp_path / "Counter.java"
    source.write_text(SOURCE, encoding="utf-8")
    matrix = generate_traceability_matrix(domain, source, reqs)
    assert matrix["rows"][0]["status"] == "UNMAPPED"   # bound 999 matches nothing
    names = [node.get("name") for node in
             _walk([{"kind": "field", "name": "x"},
                    {"guards": [{"kind": "field", "name": "y"}]}], {"field"})]
    assert set(names) == {"x", "y"}


def test_cli_traceability_fails_closed_on_missing_inputs(tmp_path):
    import argparse
    from pipeline.cli import command_generate_traceability
    args = argparse.Namespace(domain=str(tmp_path / "absent.yaml"),
                              source=str(tmp_path), requirements=str(tmp_path / "r.req"),
                              out=str(tmp_path / "m.md"), json_out=None)
    (tmp_path / "r.req").write_text("REQ-001: value must not exceed 5.\n")
    assert command_generate_traceability(args, _SilentUI()) == 2
