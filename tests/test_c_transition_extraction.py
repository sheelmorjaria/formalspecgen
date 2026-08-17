"""M6/M7: C guarded-scalar transition inference and candidate registration."""
from __future__ import annotations

import json

import pytest

from pipeline.codebase_analysis import (
    _bounds_index,
    _infer_c_transitions,
    analyze_codebase,
    infer_field_bounds,
    parse_c_enums,
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


def test_c_transitions_fail_closed_on_foreign_fields_and_pointer_returns():
    unrelated = """struct Meter { int level; };
void unrelated_tick(struct Meter *m) {
    if (m->other < 5) { m->other = m->other + 1; }
}
int *pointer_return(struct Meter *m) {
    if (m->level < 5) { m->level = m->level + 1; }
    return &m->level;
}
void empty_body(struct Meter *m) {
    (void)m;
}
void cross_field(struct Meter *m) {
    if (m->level < 5) { m->level = m->other + 1; }
}
"""
    assert _infer_c_transitions(unrelated, [("level", "int")]) == []

    # Scalar-status returns (lwIP's `static err_t tcp_process` shape) DO
    # extract: the return value is orthogonal to the state write.
    status_return = """struct Meter { int level; };
static err_t meter_step(struct Meter *m) {
    if (m->level < 5) { m->level = m->level + 1; }
    return 0;
}
"""
    transitions = _infer_c_transitions(status_return, [("level", "int")])
    assert [item["name"] for item in transitions] == ["meter_step"]


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


# ------------------------------------------------- M7 phase 1: enum resolution ---

def test_parse_c_enums_implicit_and_explicit_counters():
    assert parse_c_enums("enum { STATE_A = 0, STATE_B, STATE_C };") == \
        {"STATE_A": 0, "STATE_B": 1, "STATE_C": 2}                     # user Test 1.1
    assert parse_c_enums("enum { STATE_A = 0, STATE_B = 5, STATE_C };") == \
        {"STATE_A": 0, "STATE_B": 5, "STATE_C": 6}                     # user Test 1.2
    assert parse_c_enums(
        "enum tcp_state { CLOSED = 0, SYN_SENT, ESTABLISHED = 3 };") == \
        {"CLOSED": 0, "SYN_SENT": 1, "ESTABLISHED": 3}
    assert parse_c_enums("enum flags { ACK = 0x10, FIN = 0x01 };") == \
        {"ACK": 16, "FIN": 1}


ENUM_IF_STYLE = """enum tcp_state { CLOSED = 0, SYN_SENT, ESTABLISHED };
struct tcp_pcb { enum tcp_state state; };
void tcp_step(struct tcp_pcb *pcb) {
    if (pcb->state == SYN_SENT) { pcb->state = ESTABLISHED; }
}
"""


def test_enum_identifiers_substitute_in_if_guards_and_effects():
    enums = parse_c_enums(ENUM_IF_STYLE)                              # user Test 1.3
    transitions = _infer_c_transitions(ENUM_IF_STYLE, [("state", "int")],
                                       enums=enums)
    assert len(transitions) == 1
    assert _dump(transitions[0]["guard"]) == _dump(
        parse_jml_expression("state == 1", fields={"state"}))
    assert _dump(transitions[0]["value"]) == _dump(
        parse_jml_expression("2", fields={"state"}))


def test_bounds_infer_from_enum_typed_field_declarations():
    enums = parse_c_enums(ENUM_IF_STYLE)
    assert infer_field_bounds(ENUM_IF_STYLE, [("state", "int")],
                              enums=enums) == {"state": (0, 2)}       # user Test 1.4
    two_enums = """enum a { A0 = 0, A1 }; enum b { B0 = 0, B1, B2, B3 };
    struct s { enum a x; };"""
    assert infer_field_bounds(two_enums, [("x", "int")],
                              enums=parse_c_enums(two_enums)) == {"x": (0, 1)}


# ------------------------------------------------ M7 phase 2: switch dispatch ---

SWITCH_STYLE = """enum tcp_state { CLOSED = 0, SYN_SENT = 1, ESTABLISHED = 2,
                 FIN_WAIT_1 = 3, LAST_ACK = 4 };
struct tcp_pcb { enum tcp_state state; };

void tcp_process(struct tcp_pcb *pcb, unsigned char flags) {
    switch (pcb->state) {
        case SYN_SENT:
            if (flags == 0x10) { pcb->state = ESTABLISHED; }
            break;
        case ESTABLISHED:
            pcb->state = FIN_WAIT_1;
            break;
        case FIN_WAIT_1:
            if (pcb->state == 3) { pcb->state = LAST_ACK; }
            break;
        case LAST_ACK:
            pcb->state = CLOSED;
            break;
        default:
            break;
    }
}
"""


def _switch_transitions(notes=None):
    return _infer_c_transitions(
        SWITCH_STYLE, [("state", "int")],
        enums=parse_c_enums(SWITCH_STYLE), notes=notes)


def test_switch_case_becomes_guard_and_effect_substitutes_enum():
    transitions = _switch_transitions()
    by_name = {item["name"]: item for item in transitions}
    # user Tests 2.1 + 2.2: case SYN_SENT guards state == 1; effect = 2.
    assert _dump(by_name["tcp_process_syn_sent"]["guard"]) == _dump(
        parse_jml_expression("state == 1", fields={"state"}))
    assert _dump(by_name["tcp_process_syn_sent"]["value"]) == _dump(
        parse_jml_expression("2", fields={"state"}))
    assert _dump(by_name["tcp_process_established"]["value"]) == _dump(
        parse_jml_expression("3", fields={"state"}))
    assert set(by_name) == {"tcp_process_syn_sent", "tcp_process_established",
                            "tcp_process_fin_wait_1", "tcp_process_last_ack"}


def test_switch_inner_if_on_state_field_conjoins_the_guard():
    transitions = _switch_transitions()
    fin_wait = next(item for item in transitions
                    if item["name"] == "tcp_process_fin_wait_1")
    assert _dump(fin_wait["guard"]) == _dump(parse_jml_expression(
        "state == 3 && state == 3", fields={"state"}))                 # user Test 2.4


def test_switch_inner_if_on_unknown_identifier_drops_condition_with_note():
    notes = []
    transitions = _switch_transitions(notes=notes)
    syn_sent = next(item for item in transitions
                    if item["name"] == "tcp_process_syn_sent")
    # flags is a parameter, not state: the condition is dropped and reported.
    assert _dump(syn_sent["guard"]) == _dump(
        parse_jml_expression("state == 1", fields={"state"}))
    assert any("tcp_process" in note and "SYN_SENT" in note for note in notes)


def test_switch_fall_through_case_is_skipped():
    fall_through = """enum s { A = 0, B = 1 };
struct m { enum s state; };
void step(struct m *x) {
    switch (x->state) {
        case A:
            x->state = B;
        case B:
            x->state = A;
            break;
    }
}
"""
    notes = []
    transitions = _infer_c_transitions(fall_through, [("state", "int")],
                                       enums=parse_c_enums(fall_through),
                                       notes=notes)
    by_name = {item["name"]: item for item in transitions}             # user Test 2.3
    assert set(by_name) == {"step_b"}          # the fall-through case is not extracted
    assert any("A" in note for note in notes)


def test_lwip_style_analyze_registers_bounded_candidate(tmp_path):
    source = tmp_path / "legacy_c"; source.mkdir()
    (source / "tcp_state.c").write_text(SWITCH_STYLE + """
void tcp_connect(struct tcp_pcb *pcb) {
    if (pcb->state == CLOSED) { pcb->state = SYN_SENT; }
}
""", encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "extracted",
                              project_root=tmp_path)                   # user Test 3.1
    assert result["status"] == "EXTRACTED"
    import yaml
    payload = yaml.safe_load(
        (tmp_path / "domains" / "candidates" / "tcp_pcb.v2.yaml").read_text())
    assert payload["state_variables"] == [
        {"kind": "int", "name": "state", "bound": [0, 4], "initial": 0}]
    assert len(payload["operations"]) == 5   # four switch cases + tcp_connect
    assert any(item["code"] == "INPUT_CONDITION_DROPPED" for item in result["warnings"])


def test_enum_and_switch_fail_closed_branches():
    guards = """enum s { A = 0, B = 1 };
struct m { enum s state; int other; };
void step(struct m *x) {
    switch (x->state) {
        case A:
            break;                       /* no state write in this case */
        case UNKNOWN_LABEL:              /* not in the enum map */
            x->state = B;
            break;
        case B:
            x->other = A;                /* writes a non-state field */
            break;
    }
}
void mystery(struct m *x) {
    if (x->state == A) { x->state = NOT_AN_ENUM_CONST; }
}
"""
    enums = parse_c_enums(guards)
    notes = []
    transitions = _infer_c_transitions(guards, [("state", "int")],
                                       enums=enums, notes=notes)
    assert transitions == []
    assert any("UNKNOWN_LABEL" in note and "unknown case constant" in note
               for note in notes)

    bad_enumerator = "enum bad { X = 1 + 2, Y = 0 };"
    assert parse_c_enums(bad_enumerator) == {"Y": 0}   # non-integer value skipped

    foreign_tag = "enum z { Z0, Z1, Z2 };\nstruct q { enum not_the_tag w; };"
    assert infer_field_bounds(foreign_tag, [("w", "int")],
                              enums=parse_c_enums(foreign_tag)) == {"w": (0, 2)}


def test_unknown_switch_effect_constant_and_unreadable_source(tmp_path):
    unknown_effect = """enum s { A = 0, B = 1 };
struct m { enum s state; };
void step(struct m *x) {
    switch (x->state) {
        case B:
            x->state = NOT_AN_ENUM_CONST;
            break;
    }
}
"""
    notes = []
    assert _infer_c_transitions(unknown_effect, [("state", "int")],
                                enums=parse_c_enums(unknown_effect),
                                notes=notes) == []
    assert any("unknown effect constant" in note for note in notes)

    source = tmp_path / "legacy"; source.mkdir()
    (source / "binary.c").write_bytes(b"\xff\xfe\x00bad")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    assert result["status"] == "EXTRACTED"
    assert result["warnings"][0]["code"] == "UNPARSEABLE_SOURCE"


def test_switch_on_non_state_field_and_enum_trailing_comma():
    trailing = "enum s { A = 0, B = 1, };"          # trailing comma in the body
    assert parse_c_enums(trailing) == {"A": 0, "B": 1}
    non_state_switch = """struct m { int state; int mode; };
void flip(struct m *x) {
    switch (x->mode) {
        case 1:
            x->state = 0;
            break;
    }
}
"""
    assert _infer_c_transitions(non_state_switch, [("state", "int")],
                                enums=parse_c_enums(trailing)) == []


def test_headers_are_scanned_and_enums_are_shared_across_files(tmp_path):
    source = tmp_path / "legacy"; source.mkdir()
    (source / "tcp.h").write_text(
        "enum link_state { DOWN = 0, UP = 1 };\n"
        "struct link { enum link_state st; };\n", encoding="utf-8")
    (source / "link.c").write_text(
        "void link_bring_up(struct link *l) {\n"
        "    if (l->st == DOWN) { l->st = UP; }\n"
        "}\n", encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    assert result["status"] == "EXTRACTED"
    # the header's struct is a component, and the .c transition resolves the
    # header-defined enum (the map is shared across the C-family tree)
    assert any(item["name"] == "link" and item["lang"] == "c" for item in result["components"])
    import yaml
    payload = yaml.safe_load((tmp_path / "domains" / "candidates" / "link.v2.yaml").read_text())
    assert payload["state_variables"] == [
        {"kind": "int", "name": "st", "bound": [0, 1], "initial": 0}]
    assert {op["name"] for op in payload["operations"]} == {"link_bring_up"}


def test_pointer_fields_are_not_scalar_state(tmp_path):
    (tmp_path / "pcb.h").write_text(
        "struct pcb { struct pcb *next; int state; };\n", encoding="utf-8")
    result = analyze_codebase(tmp_path, tmp_path / "out", project_root=tmp_path)
    component = next(item for item in result["components"] if item["name"] == "pcb")
    assert component["fields"] == [{"name": "state", "type": "int"}]


def test_parse_errors_are_reported_but_wellformed_declarations_extracted(tmp_path):
    (tmp_path / "mixed.c").write_text(
        "struct good { int state; };\n"
        "void broken( {\n", encoding="utf-8")
    result = analyze_codebase(tmp_path, tmp_path / "out", project_root=tmp_path)
    assert any(item["name"] == "good" for item in result["components"])
    assert any(item["code"] == "UNPARSEABLE_SOURCE" for item in result["warnings"])


def test_parse_error_recovery_still_records_component(tmp_path):
    (tmp_path / "mixed.c").write_text(
        "struct good { int state; };\n"
        "void broken( {\n", encoding="utf-8")
    result = analyze_codebase(tmp_path, tmp_path / "out", project_root=tmp_path)
    assert any(item["name"] == "good" for item in result["components"])
    assert any(item["code"] == "UNPARSEABLE_SOURCE" for item in result["warnings"])


def test_unreadable_c_source_in_the_transition_pass(tmp_path):
    source = tmp_path / "legacy"; source.mkdir()
    (source / "proto.h").write_text("struct proto { int state; };\n", encoding="utf-8")
    (source / "bad.c").write_bytes(b"\xff\xfe\x00bad")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    assert result["status"] == "EXTRACTED"
    assert any(item["code"] == "UNPARSEABLE_SOURCE" for item in result["warnings"])
    # the struct still registers with zero transitions
    assert (tmp_path / "domains" / "candidates" / "proto.v2.yaml").exists()


def test_unresolvable_identifier_limit_fails_closed():
    unknown = """struct m { int state; };
void step(struct m *x) {
    if (x->state == UNKNOWN_LIMIT) { x->state = 2; }
}
"""
    assert _infer_c_transitions(unknown, [("state", "int")]) == []


# ------------------------------------------------ M8: TinyUSB dialect ---

TINYUSB_SHAPE = """typedef struct {
    volatile uint8_t connected;
    volatile uint8_t addressed;
    volatile uint8_t suspended;
    volatile uint8_t cfg_num;
} usbd_dev_t;

static usbd_dev_t _usbd_dev;

void dcd_event_handler(int event_id) {
    if (_usbd_dev.connected) {
        _usbd_dev.suspended = 1;
    }
    if (_usbd_dev.connected) {
        _usbd_dev.suspended = 0;
    }
    if (!_usbd_dev.suspended) {
        _usbd_dev.cfg_num = 0;
    }
}
"""

TINYUSB_FIELDS = [("connected", "int"), ("addressed", "int"),
                  ("suspended", "int"), ("cfg_num", "int")]


def test_bare_boolean_cross_field_guards_extract():
    transitions = _infer_c_transitions(TINYUSB_SHAPE, TINYUSB_FIELDS)
    by_name = {item["name"]: item for item in transitions}
    # one operation per guard; same (fn, target) pairs get deterministic suffixes
    assert set(by_name) == {"dcd_event_handler_suspended",
                            "dcd_event_handler_suspended_2",
                            "dcd_event_handler_cfg_num"}
    fields = {name for name, _ in TINYUSB_FIELDS}
    assert _dump(by_name["dcd_event_handler_suspended"]["guard"]) == _dump(
        parse_jml_expression("connected != 0", fields=fields))      # user shape 1
    assert _dump(by_name["dcd_event_handler_suspended"]["value"]) == _dump(
        parse_jml_expression("1", fields=fields))
    assert _dump(by_name["dcd_event_handler_cfg_num"]["guard"]) == _dump(
        parse_jml_expression("suspended == 0", fields=fields))      # negated form
    assert all(item["target"] in fields for item in transitions)


def test_boolean_guard_never_pairs_across_blocks():
    """tud_task trap: a guard block with only callbacks must not steal a
    later assignment elsewhere in the function."""
    trap = """typedef struct { int connected; int suspended; } dev_t;
static dev_t _dev;
void tud_task(void) {
    if (_dev.connected) {
        tud_suspend_cb(_dev.connected);
    }
    _dev.suspended = 1;
}
"""
    assert _infer_c_transitions(trap,
                                [("connected", "int"), ("suspended", "int")]) == []


def test_boolean_guard_fails_closed_on_nested_braces():
    """SOF shape: the write is fine but the guard block contains a nested
    initializer — extraction refuses rather than mis-pairing."""
    nested = """typedef struct { int suspended; int resumed; } dev_t;
static dev_t _dev;
void dcd_event_handler(int event_id) {
    if (_dev.suspended) {
        _dev.resumed = 1;
        int local = event_id;
        (void) local;
    }
}
"""
    assert _infer_c_transitions(nested,
                                [("suspended", "int"), ("resumed", "int")]) == [
        {"name": "dcd_event_handler_resumed",
         "guard": parse_jml_expression("suspended != 0",
                                       fields={"suspended", "resumed"}),
         "target": "resumed",
         "value": parse_jml_expression("1", fields={"suspended", "resumed"})}]


def test_anonymous_typedef_struct_registers_candidate(tmp_path):
    source = tmp_path / "tinyusb"; source.mkdir()
    (source / "usbd.c").write_text(TINYUSB_SHAPE, encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "extracted", project_root=tmp_path)
    assert result["status"] == "EXTRACTED"
    registered = tmp_path / "domains" / "candidates" / "usbd_dev_t.v2.yaml"
    assert registered.exists(), "anonymous typedef structs must register candidates"
    import yaml
    payload = yaml.safe_load(registered.read_text(encoding="utf-8"))
    assert payload["domain_name"] == "UsbdDevT"
    names = {var["name"] for var in payload["state_variables"]}
    assert {"connected", "addressed", "suspended", "cfg_num"} <= names
    assert {op["name"] for op in payload["operations"]} == {
        "dcd_event_handler_suspended", "dcd_event_handler_suspended_2",
        "dcd_event_handler_cfg_num"}


def test_tagged_typedef_struct_registers_tag_only(tmp_path):
    source = tmp_path / "lwip"; source.mkdir()
    (source / "tcp.c").write_text(
        "typedef struct tcp_pcb { int state; } tcp_pcb_t;\n"
        "void tcp_open(tcp_pcb_t *pcb) {\n"
        "    if (pcb->state == 0) { pcb->state = 1; }\n"
        "}\n", encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    names = {item["name"] for item in result["components"]}
    assert "tcp_pcb" in names
    assert "tcp_pcb_t" not in names      # no duplicate component from the typedef
    assert (tmp_path / "domains" / "candidates" / "tcp_pcb.v2.yaml").exists()
    assert not (tmp_path / "domains" / "candidates" / "tcp_pcb_t.v2.yaml").exists()


def test_bounds_index_first_match_wins_and_shared_index_is_equivalent():
    text = ("int f(struct m *x) { return x->level < 9; }\n"
            "int g(struct m *x) { return x->level < 3; }\n"      # second < ignored
            "enum t { A = 0, B = 4 };\n"
            "enum u { C = 0, D = 6 };\n"
            "struct s { enum t state; };\n"
            "struct s2 { enum t state; };\n"                      # second decl ignored
            "struct s3 { enum q mystery; };\n")                   # undefined tag
    fields = [("level", "int"), ("state", "int"), ("mystery", "int")]
    enums = parse_c_enums(text)
    direct = infer_field_bounds(text, fields, enums=enums)
    shared = infer_field_bounds(text, fields, enums=enums,
                                _index=_bounds_index(text))
    assert direct == shared == {"level": (0, 9), "state": (0, 4),
                                "mystery": None}


def test_boolean_guards_fail_closed_on_foreign_guard_and_constants():
    """A bare guard on a NON-state field, or an unresolvable effect constant,
    mints nothing."""
    foreign_guard = """typedef struct { int state; } dev_t;
static dev_t _dev;
void step(void) {
    if (_dev.busy) { _dev.state = 1; }
}
"""
    assert _infer_c_transitions(foreign_guard, [("state", "int")]) == []
    unknown_effect = """typedef struct { int connected; int suspended; } dev_t;
static dev_t _dev;
void step(void) {
    if (_dev.connected) { _dev.suspended = NOT_AN_ENUM_CONST; }
}
"""
    assert _infer_c_transitions(
        unknown_effect, [("connected", "int"), ("suspended", "int")]) == []
