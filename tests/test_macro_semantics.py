# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M35: semantic macro expansion — macros to V2 logic natively.

Phase 1 (dictionary, deterministic), Phase 2 (LLM proposals, recorded
with provenance, never silently trusted), Phase 3 (synthesis through the
existing deterministic extractor + real-Z3 proof of the synthesized
model's bounds invariant: Init => Inv and Inv & Trans => Inv').
"""
from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest

from pipeline.macro_semantics import (
    load_macro_dictionary, rewrite_source, synthesize_v2_from_macros,
    translate_macros, verify_macro_model)

DICTIONARY = {"container_of": "V2::StructuralRelationship",
              "READ_ONCE": "V2::Read"}

DEV_C = """struct dev {
    int state;
};

#define WRITE_ONCE(x, v) ((x) = (v))

void start(struct dev *d) {
    if (d->state == 0) {
        WRITE_ONCE(d->state, 1);
    }
}

void stop(struct dev *d) {
    if (READ_ONCE(d->state) == 1) {
        WRITE_ONCE(d->state, 0);
    }
}

struct dev *owner(struct node *n) {
    return container_of(n, struct dev, link);
}
"""

LINKED_C = """struct node { int v; struct node *next; };
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _dictionary(tmp_path):
    path = tmp_path / "macros.json"
    path.write_text(json.dumps(DICTIONARY), encoding="utf-8")
    return path


def _z3_installed() -> bool:
    return shutil.which("z3") is not None


def _ollama_up() -> bool:
    from urllib.parse import urlparse
    from pipeline import config
    try:
        parsed = urlparse(config.OLLAMA_BASE_URL)
        with socket.create_connection(
                (parsed.hostname or "localhost",
                 parsed.port or 11434), timeout=1):
            return True
    except (OSError, ValueError):
        return False


# --- Phase 1: the dictionary (deterministic) ----------------------------

def test_dictionary_loads_and_rejects_malformed(tmp_path):
    """Test 1.1: the tool loads the dictionary; malformed JSON, non-object
    payloads, and out-of-set categories fail closed with named codes."""
    loaded = load_macro_dictionary(_dictionary(tmp_path))
    assert loaded["status"] == "MACRO_DICTIONARY_LOADED"
    assert loaded["entries"] == 2
    assert loaded["dictionary"] == DICTIONARY

    bad_json = _write(tmp_path, "bad.json", "{not json")
    assert load_macro_dictionary(bad_json)["code"] == "dictionary_malformed"
    not_object = _write(tmp_path, "arr.json", "[]")
    assert load_macro_dictionary(not_object)["code"] == "dictionary_malformed"
    bad_category = _write(
        tmp_path, "cat.json", '{"X": "V2::Whatever"}')
    assert load_macro_dictionary(
        bad_category)["code"] == "dictionary_invalid_category"
    bad_key = _write(tmp_path, "key.json", '{"9BAD": "V2::Read"}')
    assert load_macro_dictionary(
        bad_key)["code"] == "dictionary_malformed"
    assert load_macro_dictionary(tmp_path / "nope.json")["code"] == \
        "input_unavailable"

    # a dictionary macro re-#defined in the source: the definition line is
    # skipped when scanning invocations
    shadowed = _write(tmp_path, "shadow.c",
                      "#define READ_ONCE(x) (x)\n"
                      "void f(struct dev *d) { READ_ONCE(d->state); }\n")
    result = translate_macros(shadowed, DICTIONARY)
    lines = [call["line"] for call in result["invocations"]["READ_ONCE"]]
    assert lines == [2]


def test_container_of_and_read_once_translate_deterministically(tmp_path):
    """Tests 1.2/1.3: container_of -> V2 structural relationship,
    READ_ONCE -> V2 read effect — dictionary hits, no LLM consulted."""
    source = _write(tmp_path, "dev.c", DEV_C)
    result = translate_macros(source, DICTIONARY, provider=None)
    assert result["status"] == "MACROS_TRANSLATED"
    assert result["dictionary_hits"] == ["READ_ONCE", "container_of"]
    read = result["translations"]["READ_ONCE"]
    assert read["category"] == "V2::Read"
    assert read["source"] == "dictionary"
    assert read["v2"]["read"] == "d->state"
    structural = result["translations"]["container_of"]
    assert structural["category"] == "V2::StructuralRelationship"
    assert structural["v2"]["relationship"] == "enclosing_structure"
    # WRITE_ONCE is #define'd but not in the dictionary: untranslated
    # without a provider — recorded, never guessed
    assert result["translations"]["WRITE_ONCE"]["source"] == "untranslated"
    assert result["llm_proposed"] == []


def test_rewrite_expands_the_kernel_idiom(tmp_path):
    """The deterministic rewrite: WRITE_ONCE(d->state, 1) becomes the plain
    guarded-write dialect assignment; the #define line itself is a
    definition, never rewritten."""
    from pipeline.macro_semantics import _v2_shape
    translations = {
        "READ_ONCE": {"category": "V2::Read"},
        "WRITE_ONCE": {"category": "V2::Write"},
    }
    rewritten = rewrite_source(DEV_C, translations)
    assert "#define WRITE_ONCE(x, v) ((x) = (v))" in rewritten
    assert "WRITE_ONCE(" not in rewritten.replace(
        "#define WRITE_ONCE(x, v) ((x) = (v))", "")
    assert "d->state = 1;" in rewritten
    assert "(d->state)" in rewritten          # READ_ONCE in a condition
    assert "container_of(n, struct dev, link)" in DEV_C  # record-only


# --- Phase 2: LLM-driven synthesis (proposals, recorded) ----------------

def test_llm_proposal_recorded_with_provenance(tmp_path, monkeypatch):
    """Test 2.1 (hermetic): the LLM classifies WRITE_ONCE as a V2 write
    effect; the proposal is recorded with provenance and never silently
    enters the trusted dictionary."""
    from pipeline import macro_semantics
    proposals = []

    def fake_propose(name, body, provider):
        proposals.append((name, body, provider))
        return "V2::Write"

    monkeypatch.setattr(macro_semantics, "_llm_propose", fake_propose)
    source = _write(tmp_path, "dev.c", DEV_C)
    result = translate_macros(source, DICTIONARY, provider="ollama")
    assert result["llm_proposed"] == ["WRITE_ONCE"]
    entry = result["translations"]["WRITE_ONCE"]
    assert entry["category"] == "V2::Write"
    assert entry["source"] == "llm_proposed"
    assert entry["body_sha256"]
    assert proposals == [("WRITE_ONCE", "((x) = (v))", "ollama")]
    # the trusted dictionary is untouched by the proposal
    assert "WRITE_ONCE" not in DICTIONARY


def test_llm_garbage_never_guesses(tmp_path, monkeypatch):
    """Two out-of-set answers are a named refusal — a category is never
    guessed for an unclassifiable macro."""
    from pipeline import macro_semantics
    monkeypatch.setattr(
        macro_semantics, "_llm_propose",
        lambda name, body, provider: (_ for _ in ()).throw(
            RuntimeError(
                f"LLM failed to classify macro {name!r} into the closed "
                "category set after two attempts")))
    source = _write(tmp_path, "dev.c", DEV_C)
    result = translate_macros(source, DICTIONARY, provider="ollama")
    assert result["code"] == "macro_translation_failed"

    monkeypatch.setattr(
        macro_semantics, "_llm_propose",
        lambda name, body, provider: (_ for _ in ()).throw(
            RuntimeError("connection refused")))
    assert translate_macros(source, DICTIONARY,
                            provider="ollama")["code"] == "llm_unavailable"


@pytest.mark.skipif(not _ollama_up(), reason="ollama not running")
def test_real_llm_classifies_write_once(tmp_path):
    """Test 2.1 (live): the real LLM proposes a V2 category for the
    unknown macro."""
    source = _write(tmp_path, "dev.c", DEV_C)
    result = translate_macros(source, DICTIONARY, provider="ollama")
    assert result["llm_proposed"] == ["WRITE_ONCE"]
    assert result["translations"]["WRITE_ONCE"]["category"] in {
        "V2::Write", "V2::Transition"}


def test_llm_propose_hermetic_paths(monkeypatch):
    """The proposal transport: structured answer accepted; garbage retried
    once then accepted; two out-of-set answers refused."""
    import pipeline.llm as llm_module
    from pipeline import macro_semantics

    answers = iter([json.dumps({"category": "V2::Write"})])

    def good_chat(provider, json_schema=None):
        def call(messages, model, temperature):
            return next(answers), "test-model", {}
        return call

    monkeypatch.setattr(llm_module, "_chat_fn", good_chat)
    assert macro_semantics._llm_propose(
        "WRITE_ONCE", "((x) = (v))", "ollama") == "V2::Write"

    stream = iter(["not json at all", json.dumps({"category": "V2::Read"})])

    def flaky_chat(provider, json_schema=None):
        def call(messages, model, temperature):
            return next(stream), "test-model", {}
        return call

    monkeypatch.setattr(llm_module, "_chat_fn", flaky_chat)
    assert macro_semantics._llm_propose(
        "M", "body", "ollama") == "V2::Read"   # retried once

    def junk_chat(provider, json_schema=None):
        def call(messages, model, temperature):
            return "garbage", "test-model", {}
        return call

    monkeypatch.setattr(llm_module, "_chat_fn", junk_chat)
    with pytest.raises(RuntimeError):
        macro_semantics._llm_propose("M", "body", "ollama")


# --- Phase 3: synthesis + Z3 proof --------------------------------------

@pytest.mark.skipif(not _z3_installed(), reason="real z3 not installed")
def test_synthesize_and_prove_with_real_z3(tmp_path, monkeypatch):
    """Tests 3.1/3.2: analyze-codebase with the macro dictionary extracts
    the V2 model from macro-hidden writes, and real Z3 proves the
    synthesized model's bounds invariant inductive."""
    from pipeline import macro_semantics
    monkeypatch.setattr(
        macro_semantics, "_llm_propose",
        lambda name, body, provider: "V2::Write")
    source = _write(tmp_path, "dev.c", DEV_C)
    result = synthesize_v2_from_macros(
        source, _dictionary(tmp_path), provider="ollama",
        project_root=tmp_path, verify=True)
    assert result["status"] == "V2_SYNTHESIZED_FROM_MACROS"
    assert result["claim"] == "MACRO_SYNTHESIS_PROVED"
    candidates = [c for c in result["candidates"] if c["operations"]]
    assert candidates, "the macro-hidden transitions must be extracted"
    for candidate in candidates:
        verification = candidate["verification"]
        assert verification["status"] == "MACRO_MODEL_SAFETY_PROVED"
        assert verification["solver"] == "z3"
        assert verification["initiation"] == "unsat"
        assert verification["consecution"] == "unsat"
        assert "(check-sat)" in verification["smt2"]


def test_extraction_works_without_z3_and_llm(tmp_path, monkeypatch):
    """CI-hermetic Phase 3: with no provider the unknown macro stays
    untranslated (no write extracted for it — honest partial), and with
    verify off no solver is consulted."""
    from pipeline import macro_semantics
    source = _write(tmp_path, "dev.c", DEV_C)
    result = synthesize_v2_from_macros(
        source, _dictionary(tmp_path), provider=None,
        project_root=tmp_path, verify=False)
    assert result["status"] == "V2_SYNTHESIZED_FROM_MACROS"
    assert result["translations"]["WRITE_ONCE"]["source"] == "untranslated"
    assert result["claim"] == "NO_PROOF"
    assert all("verification" not in c for c in result["candidates"])


def test_verify_residuals_fail_closed(tmp_path, monkeypatch):
    """Vacuous models are refused; missing z3 is named; out-of-vocabulary
    expressions fail closed."""
    vacuous = {"state_variables": [{"kind": "int", "name": "state",
                                    "initial": 0}],
               "operations": [], "tlc_invariants": []}
    assert verify_macro_model(vacuous)["code"] == "unsupported_expression"

    unknown_field = {
        "state_variables": [{"kind": "int", "name": "state", "initial": 0}],
        "operations": [{"guards": [{"expression": {
            "kind": "eq", "left": {"kind": "field", "name": "ghost"},
            "right": {"kind": "integer", "value": 1}}}],
            "effects": [{"target": "state",
                         "value": {"kind": "integer", "value": 1}}]}],
        "tlc_invariants": [{"expression": {
            "kind": "gte", "left": {"kind": "field", "name": "state"},
            "right": {"kind": "integer", "value": 0}}}]}
    assert verify_macro_model(unknown_field)["code"] == \
        "unsupported_expression"

    good = {"state_variables": [{"kind": "int", "name": "state",
                                 "bound": [0, 1], "initial": 0}],
            "operations": [{"guards": [], "effects": [
                {"target": "state",
                 "value": {"kind": "integer", "value": 1}}]}],
            "tlc_invariants": [{"expression": {
                "kind": "and",
                "left": {"kind": "gte",
                         "left": {"kind": "field", "name": "state"},
                         "right": {"kind": "integer", "value": 0}},
                "right": {"kind": "lte",
                          "left": {"kind": "field", "name": "state"},
                          "right": {"kind": "integer", "value": 1}}}}]}
    monkeypatch.setenv("Z3_BIN", "/nonexistent/z3")
    assert verify_macro_model(good)["code"] == "z3_unavailable"
    monkeypatch.undo()

    from subprocess import CompletedProcess
    from unittest.mock import patch
    with patch("subprocess.run", side_effect=TimeoutError("slow")):
        assert verify_macro_model(good)["code"] == "z3_timeout"
    with patch("subprocess.run", return_value=CompletedProcess(
            args=[], returncode=0,
            stdout='(error "line 1: bad")\nsat\nunsat\n', stderr="")):
        assert verify_macro_model(good)["code"] == "smt_encoding_error"
    with patch("subprocess.run", return_value=CompletedProcess(
            args=[], returncode=0, stdout="nothing parseable", stderr="")):
        assert verify_macro_model(good)["code"] == "z3_no_verdict"

    unsupported_kind = {
        "state_variables": [{"kind": "int", "name": "state", "initial": 0}],
        "operations": [{"guards": [{"expression": {
            "kind": "mystery", "x": 1}}], "effects": []}],
        "tlc_invariants": [{"expression": {
            "kind": "gte", "left": {"kind": "field", "name": "state"},
            "right": {"kind": "integer", "value": 0}}}]}
    assert verify_macro_model(unsupported_kind)["code"] == \
        "unsupported_expression"

    if _z3_installed():
        proved = verify_macro_model(good)
        assert proved["status"] == "MACRO_MODEL_SAFETY_PROVED"
        assert proved["claim"] == "MACRO_SYNTHESIS_PROVED"


@pytest.mark.skipif(not _z3_installed(), reason="real z3 not installed")
def test_real_z3_refuses_an_unsafe_model():
    """A transition writing outside the invariant's bounds is REFUSED —
    the proof can fail; it is never decorative."""
    unsafe = {"state_variables": [{"kind": "int", "name": "state",
                                   "bound": [0, 1], "initial": 0}],
              "operations": [{"guards": [], "effects": [
                  {"target": "state",
                   "value": {"kind": "integer", "value": 7}}]}],
              "tlc_invariants": [{"expression": {
                  "kind": "and",
                  "left": {"kind": "gte",
                           "left": {"kind": "field", "name": "state"},
                           "right": {"kind": "integer", "value": 0}},
                  "right": {"kind": "lte",
                            "left": {"kind": "field", "name": "state"},
                            "right": {"kind": "integer", "value": 1}}}}]}
    verdict = verify_macro_model(unsafe)
    assert verdict["status"] == "MACRO_MODEL_SAFETY_FAILED"
    assert verdict["consecution"] == "sat"
    assert verdict["claim"] == "NO_PROOF"


def test_out_of_lane_sources_fail_closed(tmp_path):
    source = _write(tmp_path, "L.rs", "#define X() y")
    assert translate_macros(source, DICTIONARY)["code"] == \
        "UNSUPPORTED_BOUNDARY"
    assert translate_macros(tmp_path / "nope.c", DICTIONARY)["code"] == \
        "input_unavailable"
    assert synthesize_v2_from_macros(
        source, _dictionary(tmp_path))["code"] == "UNSUPPORTED_BOUNDARY"


def test_encoding_and_rewrite_edges(tmp_path):
    """The deterministic edges: guard macros record-only, malformed arity
    left verbatim, unclosed invocations clamped, bracketed args split,
    boolean fields/literals/unaries encoded, untouched fields framed, and
    out-of-model effect targets refused."""
    from pipeline import macro_semantics as ms

    bad = _write(tmp_path, "bad.json", "{")
    src = _write(tmp_path, "dev.c", DEV_C)
    assert ms.synthesize_v2_from_macros(
        src, bad)["code"] == "dictionary_malformed"

    assert ms._v2_shape("V2::Guard",
                        [{"args": ["d->state"]}]) == {"guard": ["d->state"]}
    assert ms._v2_shape("V2::Guard", [{"args": []}]) == {"guard": None}

    assert "SET(x);" in ms.rewrite_source(
        "SET(x);\n", {"SET": {"category": "V2::Write"}})

    close, args = ms._balanced_call("MACRO(a, b", 5)
    assert close == len("MACRO(a, b") - 1 and args == "a, "
    assert ms._split_args("f(a[0]), 2") == ["f(a[0])", "2"]

    fields = {"locked": "bool", "count": "int"}
    assert ms._smt({"kind": "boolean", "value": True}, fields) == "true"
    assert ms._smt({"kind": "boolean", "value": False}, fields) == "false"
    assert ms._smt({"kind": "not", "operand": {
        "kind": "field", "name": "locked"}}, fields) == "(not s_locked)"
    assert ms._smt({"kind": "neg", "operand": {
        "kind": "integer", "value": 3}}, fields) == "(- 3)"
    with pytest.raises(ms._Unsupported):
        ms._smt({"no_kind": 1}, fields)

    payload = {
        "state_variables": [
            {"kind": "bool", "name": "locked", "initial": False},
            {"kind": "int", "name": "count", "initial": "0",
             "bound": [0, 3]}],
        "operations": [{"guards": [{"expression": {
            "kind": "eq", "left": {"kind": "field", "name": "count"},
            "right": {"kind": "integer", "value": 0}}}],
            "effects": [{"target": "count",
                         "value": {"kind": "integer", "value": 1}}]}],
        "tlc_invariants": [{"expression": {
            "kind": "gte", "left": {"kind": "field", "name": "count"},
            "right": {"kind": "integer", "value": 0}}}]}
    smt = ms._encode_smt2(payload)
    assert "(= s_locked false)" in smt          # boolean initial
    assert "(= s_count 0)" in smt               # string initial "0"
    assert "(= s_locked_next s_locked)" in smt  # frame: untouched field
    bad_target = dict(
        payload, operations=[{"guards": [], "effects": [
            {"target": "ghost",
             "value": {"kind": "integer", "value": 1}}]}])
    with pytest.raises(ms._Unsupported):
        ms._encode_smt2(bad_target)
