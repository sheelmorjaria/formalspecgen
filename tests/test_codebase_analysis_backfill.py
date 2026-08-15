"""Coverage backfill for codebase_analysis fallback paths and canonical-draft guards."""
from __future__ import annotations

import io
from types import SimpleNamespace

import pytest
from rich.console import Console

from pipeline import cli
from pipeline.codebase_analysis import (
    _infer_java_transitions,
    _polyglot_declarations,
    analyze_codebase,
    extract_components_ts,
)

RUST_STRUCT = "pub struct Sensor { pub reading: i32, pub active: bool }\n"
C_STRUCT = "struct Node { int value; bool flag; };\n"
CPP_STRUCT = "class Widget { public: int size; bool on; };\n"


def _ui():
    return cli.TerminalUI(Console(file=io.StringIO(), force_terminal=False),
                          lambda _prompt: "answer")


def _draft_args(**overrides):
    base = dict(requirement="counter", provider="ollama", model=None, no_clarify=True,
                lang="java", canonical_domain=None, out_file=None, fallback_provider=None,
                out=None, max_attempts=None, resample_budget=None, feedback_budget=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_polyglot_fallback_extracts_rust_and_c_family_structs(tmp_path):
    rust = tmp_path / "sensor.rs"
    rust.write_text(RUST_STRUCT, encoding="utf-8")
    assert _polyglot_declarations(rust, RUST_STRUCT) == [
        {"name": "Sensor", "interface": False,
         "fields": [("reading", "int"), ("active", "boolean")]}]

    c = tmp_path / "node.c"
    c.write_text(C_STRUCT, encoding="utf-8")
    assert _polyglot_declarations(c, C_STRUCT) == [
        {"name": "Node", "interface": False,
         "fields": [("value", "int"), ("flag", "boolean")]}]

    cpp = tmp_path / "widget.cpp"
    cpp.write_text(CPP_STRUCT, encoding="utf-8")
    assert _polyglot_declarations(cpp, CPP_STRUCT) == [
        {"name": "Widget", "interface": False,
         "fields": [("size", "int"), ("on", "boolean")]}]


def test_extract_components_ts_unsupported_suffix_and_unreadable_path(tmp_path):
    textfile = tmp_path / "notes.txt"
    textfile.write_text("public class Ignored {}", encoding="utf-8")
    assert extract_components_ts(textfile) is None
    assert extract_components_ts(tmp_path) is None  # read_text on a directory -> OSError


def test_analyze_codebase_warns_on_java_parse_error(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Broken.java").write_text("class Broken {", encoding="utf-8")
    result = analyze_codebase(tmp_path / "src", tmp_path / "out", tmp_path)
    assert result["status"] == "EXTRACTED"
    assert any(w["code"] == "UNPARSEABLE_SOURCE" and "parse error" in w["message"]
               for w in result["warnings"])


def test_infer_java_transitions_finds_multiple_methods():
    text = ("public class Counter { private int count; "
            "public void bump() { if (count > 5) { count = count + 1; } } "
            "public void fine() { if (count < 9) { count = count + 2; } } }")
    transitions = _infer_java_transitions(text, [("count", "int")])
    assert [t["name"] for t in transitions] == ["bump", "fine"]
    # Fields the regex matches but the class never declared are skipped.
    stranger = ("public class Counter { private int count; "
                "public void bump() { if (other > 5) { other = other + 1; } } }")
    assert _infer_java_transitions(stranger, [("count", "int")]) == []


def test_java_canonical_draft_rejects_unsafe_domain_identifier(tmp_path):
    args = _draft_args(canonical_domain="bad-name", out_file=str(tmp_path / "X.java"))
    store = cli.SessionStore(tmp_path)
    # command_draft converts the guard failure into a nonzero exit code.
    assert cli.command_draft(args, _ui(), store, store.empty()) != 0
    assert not (tmp_path / "X.java").exists()


def test_canonical_rust_draft_requires_reviewed_domain_file(tmp_path):
    args = _draft_args(lang="rust", canonical_domain="ghost",
                       out_file=str(tmp_path / "Ghost.rs"))
    store = cli.SessionStore(tmp_path)
    with pytest.raises(ValueError, match="reviewed V2 domain"):
        cli._canonical_rust_draft(args, _ui(), store, store.empty(), "ghost")
