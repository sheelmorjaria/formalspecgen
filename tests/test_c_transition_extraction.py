"""M6: C guarded-scalar transition inference and candidate registration."""
from __future__ import annotations

import json

import pytest

from pipeline.codebase_analysis import (
    _infer_c_transitions,
    analyze_codebase,
    infer_field_bounds,
)
from pipeline.jml_ast import parse_jml_expression

CONNECTION_C = """struct Connection {
    int conn_state;
};

int connection_state_valid(struct Connection *c) {
    return c->conn_state <= 2;
}

void connection_open(struct Connection *c) {
    if (c->conn_state == 0) {
        c->conn_state = 1;
    }
}

void connection_establish(struct Connection *c) {
    if (c->conn_state == 1) {
        c->conn_state = 2;
    }
}

void connection_close(struct Connection *c) {
    if (c->conn_state != 0) {
        c->conn_state = 0;
    }
}
"""


def _dump(node):
    return node.model_dump(mode="json")


def test_c_literal_transitions_compile_to_strict_v2_asts():
    transitions = _infer_c_transitions(CONNECTION_C, [("conn_state", "int")])
    by_name = {item["name"]: item for item in transitions}
    assert set(by_name) == {"connection_open", "connection_establish",
                            "connection_close"}
    assert _dump(by_name["connection_open"]["guard"]) == _dump(
        parse_jml_expression("conn_state == 0", fields={"conn_state"}))
    assert _dump(by_name["connection_open"]["value"]) == _dump(
        parse_jml_expression("1", fields={"conn_state"}))
    assert _dump(by_name["connection_establish"]["guard"]) == _dump(
        parse_jml_expression("conn_state == 1", fields={"conn_state"}))
    assert _dump(by_name["connection_close"]["guard"]) == _dump(
        parse_jml_expression("conn_state != 0", fields={"conn_state"}))
    assert all(item["target"] == "conn_state" for item in transitions)


def test_c_incremental_transition_and_dot_access():
    incremental = """struct Meter { int level; };
void meter_bump(struct Meter *m) {
    if (m->level < 5) { m->level = m->level + 1; }
}
void meter_stack(struct Meter m) {
    if (m.level >= 0) { m.level = m.level + 2; }
}
"""
    transitions = _infer_c_transitions(incremental, [("level", "int")])
    by_name = {item["name"]: item for item in transitions}
    assert _dump(by_name["meter_bump"]["guard"]) == _dump(
        parse_jml_expression("level < 5", fields={"level"}))
    assert _dump(by_name["meter_bump"]["value"]) == _dump(
        parse_jml_expression("level + 1", fields={"level"}))
    assert _dump(by_name["meter_stack"]["value"]) == _dump(
        parse_jml_expression("level + 2", fields={"level"}))


def test_c_transitions_fail_closed_on_foreign_fields_and_returning_functions():
    unrelated = """struct Meter { int level; };
void unrelated_tick(struct Meter *m) {
    if (m->other < 5) { m->other = m->other + 1; }
}
int not_void(struct Meter *m) {
    if (m->level < 5) { m->level = m->level + 1; }
    return m->level;
}
void empty_body(struct Meter *m) {
    (void)m;
}
void cross_field(struct Meter *m) {
    if (m->level < 5) { m->level = m->other + 1; }
}
"""
    assert _infer_c_transitions(unrelated, [("level", "int")]) == []


def test_bounds_inference_accepts_leq_comparisons():
    assert infer_field_bounds(CONNECTION_C, [("conn_state", "int")]) == \
        {"conn_state": (0, 2)}
    less_than = "int f(struct Connection *c) { return c->conn_state < 3; }"
    assert infer_field_bounds(less_than, [("conn_state", "int")]) == \
        {"conn_state": (0, 3)}


def test_analyze_registers_a_c_v2_candidate_with_transitions(tmp_path):
    source = tmp_path / "legacy_c"; source.mkdir()
    (source / "connection.c").write_text(CONNECTION_C, encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "extracted",
                              project_root=tmp_path)
    assert result["status"] == "EXTRACTED"
    registered = tmp_path / "domains" / "candidates" / "connection.v2.yaml"
    assert registered.exists(), "C sources must register V2 candidates"
    import yaml
    payload = yaml.safe_load(registered.read_text(encoding="utf-8"))
    assert payload["domain_name"] == "Connection"
    assert payload["review_status"] == "unreviewed"
    assert payload["state_variables"] == [
        {"kind": "int", "name": "conn_state", "bound": [0, 2], "initial": 0}]
    assert {op["name"] for op in payload["operations"]} == \
        {"connection_open", "connection_establish", "connection_close"}
    opening = next(op for op in payload["operations"]
                   if op["name"] == "connection_open")
    assert opening["guards"][0]["expression"] == {
        "kind": "eq", "left": {"kind": "field", "name": "conn_state"},
        "right": {"kind": "integer", "value": 0}}
    assert opening["effects"][0]["value"] == {"kind": "integer", "value": 1}
    assert opening["frame"] == ["conn_state"]
    invariant = payload["tlc_invariants"][0]["expression"]
    assert invariant["left"]["left"]["name"] == "conn_state"
    assert invariant["right"]["right"]["value"] == 2
    skeleton = json.loads((tmp_path / "extracted" / "connection.v2.json")
                          .read_text(encoding="utf-8"))
    assert skeleton["warnings"] == []  # bounded: no manual-review warning
