"""Unit tests for the Code -> Math -> Natural Language documentation lane."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from pipeline import cli
from pipeline.code_documentation import (
    document_code,
    generate_narrative,
    render_infix,
    render_nl_document,
    render_predicate,
)

INVENTORY_JAVA = """public class Inventory {
    private int stock;

    public Inventory() {
        this.stock = 5;
    }

    public void reserve() {
        if (stock > 0) {
            stock = stock - 1;
        }
    }

    public void restock() {
        if (stock < 5) {
            stock = stock + 1;
        }
    }
}
"""

TRAFFIC_JAVA = """public class TrafficIntersection {
    private boolean trainPresent;
    private boolean carPresent;

    public void toggleTrain() {
        if (trainPresent == false) {
            trainPresent = true;
        }
    }
}
"""

NARRATIVE_JSON = json.dumps({
    "overview": "The Inventory domain manages a bounded stock level.",
    "invariant_prose": {"inv1": "Safety Rule: The system must never allow a simultaneous "
                                "train and car crossing."},
})


def _documented(tmp_path: Path, source_text: str = INVENTORY_JAVA,
                name: str = "Inventory.java") -> tuple[dict, str]:
    source = tmp_path / name
    source.write_text(source_text, encoding="utf-8")
    out = tmp_path / "docs" / f"{source.stem}.md"
    verdict = document_code(source, out, project_root=tmp_path, no_llm=True)
    return verdict, out.read_text(encoding="utf-8")


# ------------------------------------------------------------- Milestone 1 ---


def test_state_variable_sentence_is_exact(tmp_path):
    _, document = _documented(tmp_path)
    assert ("The system tracks a 'stock' value, starting at 5, which must always remain "
            "between 0 and 5." in document)


def test_operation_sentence_is_exact(tmp_path):
    _, document = _documented(tmp_path)
    assert ("The 'reserve' operation can only be called if stock is greater than 0. "
            "When called, it decreases the stock by 1." in document)


def test_invariants_render_as_safety_rules(tmp_path):
    _, document = _documented(tmp_path)
    assert "Safety Rule: stock >= 0 and stock <= 5 must always hold." in document


def test_boolean_state_sentence(tmp_path):
    verdict, document = _documented(tmp_path, TRAFFIC_JAVA, "TrafficIntersection.java")
    assert verdict["status"] == "DOCUMENTED"
    assert "The system tracks a boolean 'trainPresent' value, initially false." in document


def test_render_predicate_vocabulary():
    assert render_predicate({"kind": "gt", "left": {"kind": "field", "name": "stock"},
                             "right": {"kind": "integer", "value": 0}}) == "stock is greater than 0"
    assert render_predicate({"kind": "lte", "left": {"kind": "field", "name": "count"},
                             "right": {"kind": "integer", "value": 5}}) == "count is at most 5"
    assert render_predicate({"kind": "and", "left": {"kind": "field", "name": "a"},
                             "right": {"kind": "field", "name": "b"}}) == "a and b"
    assert render_predicate({"kind": "implies",
                             "left": {"kind": "field", "name": "a"},
                             "right": {"kind": "boolean", "value": False}}) == "if a then false"


def test_render_rejects_unknown_kind():
    for renderer in (render_predicate, render_infix):
        try:
            renderer({"kind": "quantifier"})
        except ValueError:
            pass
        else:
            raise AssertionError("unknown kind must fail closed")


def test_narrative_is_injected_and_prose_reaches_invariants(tmp_path):
    source = tmp_path / "Inventory.java"
    source.write_text(INVENTORY_JAVA, encoding="utf-8")
    out = tmp_path / "docs" / "Inventory.md"
    with patch("pipeline.code_documentation._chat_fn",
               return_value=lambda *_args: (NARRATIVE_JSON, "fixture", {})):
        verdict = document_code(source, out, project_root=tmp_path)
    assert verdict["status"] == "DOCUMENTED"
    assert verdict["narrative_source"] == "provider"
    document = out.read_text(encoding="utf-8")
    assert "The Inventory domain manages a bounded stock level." in document
    assert ("The system must never allow a simultaneous train and car crossing."
            in document)


def test_narrative_failure_falls_back_to_deterministic(tmp_path):
    source = tmp_path / "Inventory.java"
    source.write_text(INVENTORY_JAVA, encoding="utf-8")
    out = tmp_path / "docs" / "Inventory.md"
    with patch("pipeline.code_documentation._chat_fn", side_effect=RuntimeError("offline")):
        verdict = document_code(source, out, project_root=tmp_path)
    assert verdict["status"] == "DOCUMENTED"
    assert verdict["narrative_source"] == "deterministic_fallback"
    assert "tracks a 'stock' value" in out.read_text(encoding="utf-8")


def test_generate_narrative_rejects_malformed_output():
    with patch("pipeline.code_documentation._chat_fn",
               return_value=lambda *_args: ("not json at all", "fixture", {})):
        assert generate_narrative({"module_name": "x"}, "ollama", None) is None


# ------------------------------------------------------------- Milestone 2 ---


def test_cli_document_code_writes_markdown(tmp_path):
    source = tmp_path / "LegacyCounter.java"
    source.write_text("public class LegacyCounter { private int count; "
                      "public void inc() { if (count < 5) { count = count + 1; } } }",
                      encoding="utf-8")
    out = tmp_path / "docs" / "LegacyCounter.md"
    assert cli.main(["document-code", str(source), "--out", str(out),
                     "--project-root", str(tmp_path), "--no-llm",
                     "--json", str(tmp_path / "verdict.json")]) == 0
    document = out.read_text(encoding="utf-8")
    assert "# State Variables" in document
    assert "# Operations" in document
    assert "'inc' operation" in document
    verdict = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["status"] == "DOCUMENTED"
    assert verdict["claim"] == "UNREVIEWED_EXTRACTION_DOCUMENTATION"
    assert (tmp_path / "domains" / "candidates" / "legacy_counter.v2.yaml").exists()


def test_document_code_fails_closed_on_unbounded_state(tmp_path):
    source = tmp_path / "Spinner.java"
    source.write_text("public class Spinner { private int ticks; "
                      "public void spin() { ticks = ticks + 1; } }", encoding="utf-8")
    verdict = document_code(source, tmp_path / "docs" / "Spinner.md",
                            project_root=tmp_path, no_llm=True)
    assert verdict["status"] == "FAIL"
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["code"] == "UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW"
    assert not (tmp_path / "docs" / "Spinner.md").exists()


def test_document_code_fail_paths(tmp_path):
    missing = document_code(tmp_path / "Nope.java", tmp_path / "docs" / "Nope.md",
                            project_root=tmp_path, no_llm=True)
    assert missing["status"] == "FAIL"
    assert missing["code"] == "input_unavailable"

    broken = tmp_path / "Broken.java"
    broken.write_text("public class Broken {", encoding="utf-8")
    unparseable = document_code(broken, tmp_path / "docs" / "Broken.md",
                                project_root=tmp_path, no_llm=True)
    assert unparseable["code"] == "UNPARSEABLE_SOURCE"


def test_document_code_documents_non_java_state_only(tmp_path):
    # Bool-only struct: int fields in non-Java sources can never infer a bound,
    # so they fail closed; booleans carry no bound requirement.
    source = tmp_path / "sensor.rs"
    source.write_text("pub struct Sensor { pub active: bool, pub armed: bool }\n",
                      encoding="utf-8")
    verdict = document_code(source, tmp_path / "docs" / "Sensor.md",
                            project_root=tmp_path, no_llm=True)
    assert verdict["status"] == "DOCUMENTED"
    assert verdict["operation_inference"] == "java_only"
    document = (tmp_path / "docs" / "Sensor.md").read_text(encoding="utf-8")
    assert "active" in document
    assert "No operations were inferred" in document


# ------------------------------------------------------------- Milestone 3 ---


def test_markdown_structure_and_evidence_footer(tmp_path):
    verdict, document = _documented(tmp_path)
    assert document.startswith("# Inventory")
    for header in ("# State Variables", "# Operations", "# Safety Invariants"):
        assert header in document
    assert ("*This documentation was auto-generated from a formal V2 extraction model. "
            "Review Status: UNREVIEWED.*" in document)
    assert verdict["source_sha256"] in document
    assert verdict["schema_valid"] is True
    assert verdict["validation"] == {"status": "NOT_RUN", "reason": "human review required"}
