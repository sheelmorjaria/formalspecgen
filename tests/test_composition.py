# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic multi-tier composition: spec schema, binding resolution, lint, coupling."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pipeline import composition
from pipeline.composition import (
    CompositionError,
    CompositionSpec,
    UnsupportedCompositionBoundary,
    analyze_coupling,
    lint_composition,
    parse_composition,
    resolve_bindings,
)

HEX64 = "a" * 64


def reviewed_spec(domain="Gate", module="gate", *, door_initial=0):
    return {
        "schema_version": 2,
        "review_status": "reviewed",
        "domain_name": domain,
        "module_name": module,
        "state_variables": [
            {"kind": "int", "name": "door", "bound": [0, 1], "initial": door_initial}
        ],
        "operations": [
            {
                "name": "Open",
                "return_type": "void",
                "failure_semantics": "unavailable",
                "guards": [
                    {
                        "id": "g1",
                        "expression": {
                            "kind": "eq",
                            "left": {"kind": "field", "name": "door"},
                            "right": {"kind": "integer", "value": 0},
                        },
                    }
                ],
                "effects": [
                    {
                        "id": "e1",
                        "target": "door",
                        "value": {"kind": "integer", "value": 1},
                    }
                ],
                "frame": ["door"],
                "exception_type": None,
                "exception_trigger": None,
            },
            {
                "name": "TryToggle",
                "return_type": "boolean",
                "failure_semantics": "false_and_stutter",
                "guards": [],
                "effects": [
                    {
                        "id": "e1",
                        "target": "door",
                        "value": {
                            "kind": "old",
                            "expression": {"kind": "field", "name": "door"},
                        },
                    }
                ],
                "frame": ["door"],
                "exception_type": None,
                "exception_trigger": None,
            },
        ],
        "tlc_invariants": [
            {
                "id": "DoorBound",
                "expression": {
                    "kind": "lte",
                    "left": {"kind": "field", "name": "door"},
                    "right": {"kind": "integer", "value": 1},
                },
            }
        ],
        "accepted_candidate_sha256": HEX64,
        "accepted_evidence_sha256": "b" * 64,
    }


def architecture_value():
    return {
        "name": "GateSystem",
        "description": "gate plus control panel",
        "components": [
            {
                "id": "gate",
                "name": "Gate",
                "layer": "entities",
                "kind": "class",
                "operations": [],
                "dependencies": [],
            },
            {
                "id": "panel",
                "name": "Panel",
                "layer": "use_cases",
                "kind": "class",
                "operations": [],
                "dependencies": [{"target": "gate", "abstraction": True}],
            },
        ],
        "use_cases": [],
    }


def composition_value():
    return {
        "system_name": "GateSystem",
        "architecture": architecture_value(),
        "bindings": [
            {"component": "gate", "module_name": "gate"},
            {"component": "panel", "module_name": "panel"},
        ],
        "use_cases": [
            {"name": "OpenGate", "steps": [{"component": "gate", "operation": "Open"}]},
            {
                "name": "PanelOpensGate",
                "steps": [{"component": "panel", "operation": "Open"}],
            },
        ],
    }


@pytest.fixture()
def v2_dir(tmp_path):
    directory = tmp_path / "v2"
    directory.mkdir()
    (directory / "gate.json").write_text(
        json.dumps(reviewed_spec()), encoding="utf-8")
    (directory / "panel.json").write_text(
        json.dumps(reviewed_spec(domain="Panel", module="panel")),
        encoding="utf-8")
    return directory


def test_parse_composition_strict_schema():
    spec = parse_composition(composition_value())
    assert isinstance(spec, CompositionSpec)
    assert spec.system_name == "GateSystem"
    with pytest.raises(ValidationError):
        parse_composition({**composition_value(), "surprise": 1})
    with pytest.raises(ValidationError):
        parse_composition({**composition_value(), "use_cases": []})
    with pytest.raises(ValidationError):
        parse_composition(
            {**composition_value(),
             "use_cases": [{"name": "X", "steps": []}]})


def test_parse_composition_rejects_duplicate_bindings_and_names():
    value = composition_value()
    value["bindings"].append({"component": "gate", "module_name": "gate"})
    with pytest.raises(ValidationError):
        parse_composition(value)
    value = composition_value()
    value["use_cases"].append({"name": "OpenGate", "steps": [
        {"component": "gate", "operation": "Open"}]})
    with pytest.raises(ValidationError):
        parse_composition(value)


def test_resolve_bindings_happy_path(v2_dir):
    spec = parse_composition(composition_value())
    resolved = resolve_bindings(spec, v2_dir)
    assert set(resolved) == {"gate", "panel"}
    assert resolved["gate"].domain_name == "Gate"
    assert resolved["panel"].module_name == "panel"


def test_resolve_bindings_fails_closed(v2_dir):
    spec = parse_composition(composition_value())
    (v2_dir / "panel.json").unlink()
    with pytest.raises(CompositionError, match="panel"):
        resolve_bindings(spec, v2_dir)

    (v2_dir / "panel.json").write_text(
        json.dumps(reviewed_spec(domain="Panel", module="panel")), encoding="utf-8")
    spec = parse_composition({**composition_value(),
                              "bindings": [
                                  {"component": "gate", "module_name": "gate"},
                                  {"component": "ghost", "module_name": "panel"},
                              ]})
    with pytest.raises(CompositionError, match="ghost"):
        resolve_bindings(spec, v2_dir)

    spec = parse_composition({**composition_value(),
                              "bindings": [
                                  {"component": "gate", "module_name": "gate"},
                              ]})
    with pytest.raises(CompositionError, match="panel"):
        resolve_bindings(spec, v2_dir)

    unreviewed = reviewed_spec(domain="Panel", module="panel")
    unreviewed["review_status"] = "unreviewed"
    unreviewed.pop("accepted_candidate_sha256")
    unreviewed.pop("accepted_evidence_sha256")
    (v2_dir / "panel.json").write_text(json.dumps(unreviewed), encoding="utf-8")
    spec = parse_composition(composition_value())
    with pytest.raises(CompositionError, match="reviewed"):
        resolve_bindings(spec, v2_dir)


def test_lint_composition_inherits_solid_and_checks_bindings(v2_dir):
    spec = parse_composition(composition_value())
    resolved = resolve_bindings(spec, v2_dir)
    assert lint_composition(spec, resolved) == []

    inverted = composition_value()
    inverted["architecture"]["components"][1]["layer"] = "infrastructure"
    inverted["architecture"]["components"][0]["dependencies"] = [
        {"target": "panel", "abstraction": True}]
    inverted["architecture"]["components"][1]["dependencies"] = []
    findings = lint_composition(parse_composition(inverted), resolved)
    assert any(item["code"] == "dependency-inversion" for item in findings)

    unknown_op = composition_value()
    unknown_op["use_cases"][0]["steps"][0]["operation"] = "Slam"
    findings = lint_composition(parse_composition(unknown_op), resolved)
    assert any(item["code"] == "composition-unknown-operation" for item in findings)

    boolean_op = composition_value()
    boolean_op["use_cases"][0]["steps"][0]["operation"] = "TryToggle"
    findings = lint_composition(parse_composition(boolean_op), resolved)
    assert any(item["code"] == "composition-boolean-operation" for item in findings)

    repeated = composition_value()
    repeated["use_cases"][0]["steps"].append(
        {"component": "gate", "operation": "Open"})
    findings = lint_composition(parse_composition(repeated), resolved)
    assert any(item["code"] == "composition-repeated-component" for item in findings)

    findings = lint_composition(spec, resolved=None)
    assert any(item["code"] == "composition-binding-unresolved" for item in findings)


def test_analyze_coupling_partitions_step_guards(v2_dir):
    spec = parse_composition(composition_value())
    resolved = resolve_bindings(spec, v2_dir)
    report = analyze_coupling(spec.use_cases[0], resolved)
    assert report["use_case"] == "OpenGate"
    assert report["caller_preconditions"] == ["gate.door == 0"]
    obligation = report["coupling_obligations"][0]
    assert obligation["component"] == "gate"
    assert obligation["step"] == 1
    assert obligation["fact"] == "gate.door == 0"
    assert obligation["operation"] == "Open"

    repeated = spec.use_cases[0].model_copy(deep=True)
    repeated.steps.append(composition.CompositionStep(
        component="gate", operation="Open"))
    with pytest.raises(UnsupportedCompositionBoundary):
        analyze_coupling(repeated, resolved)

    missing = spec.use_cases[0].model_copy(deep=True)
    missing.steps[0] = composition.CompositionStep(
        component="gate", operation="Slam")
    with pytest.raises(UnsupportedCompositionBoundary, match="Slam"):
        analyze_coupling(missing, resolved)

    boolean = spec.use_cases[0].model_copy(deep=True)
    boolean.steps[0] = composition.CompositionStep(
        component="gate", operation="TryToggle")
    with pytest.raises(UnsupportedCompositionBoundary, match="TryToggle"):
        analyze_coupling(boolean, resolved)


def test_resolve_bindings_default_directory(monkeypatch, v2_dir):
    spec = parse_composition(composition_value())
    monkeypatch.setattr(composition.config, "ROOT", v2_dir.parent)
    directory = v2_dir.parent / "domains" / "v2"
    directory.mkdir(parents=True)
    directory.joinpath("gate.json").write_text(
        json.dumps(reviewed_spec()), encoding="utf-8")
    directory.joinpath("panel.json").write_text(
        json.dumps(reviewed_spec(domain="Panel", module="panel")),
        encoding="utf-8")
    assert set(resolve_bindings(spec)) == {"gate", "panel"}


def test_shipped_composition_example_parses():
    example = Path(__file__).resolve().parents[1] / "domains" / "examples" / \
        "composition" / "secure_entry.composition.json"
    spec = parse_composition(example.read_text(encoding="utf-8"))
    assert spec.system_name == "SecureEntry"
    assert {binding.module_name for binding in spec.bindings} == {"smart_lock"}
    findings = lint_composition(spec)
    assert not [item for item in findings
                if item["code"] != "composition-binding-unresolved"]


def test_lint_composition_structural_findings_without_resolution():
    value = composition_value()
    value["bindings"].append({"component": "ghost", "module_name": "gate"})
    value["use_cases"].append({"name": "Mystery", "steps": [
        {"component": "stranger", "operation": "Open"}]})
    codes = {item["code"] for item in lint_composition(parse_composition(value))}
    assert "composition-unknown-component" in codes
    assert "composition-missing-binding" in codes
    assert "composition-binding-unresolved" in codes


def test_render_qualified_full_expression_subset():
    from pipeline.domain_v2 import (
        BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr)
    node = BinaryExpr(kind="and", left=NotExpr(expression=FieldExpr(name="door")),
                      right=OldExpr(expression=FieldExpr(name="latch")))
    assert composition.render_qualified(node, "gate") == \
        "(!(gate.door) && \\old(gate.latch))"
    assert composition.render_qualified(FieldExpr(name="door"), "gate",
                                        pre_state=True) == "\\old(gate.door)"
    assert composition.render_qualified(IntegerExpr(value=7), "gate") == "7"
    assert composition.render_qualified(BooleanExpr(value=False), "gate") == "false"
    bogus = BinaryExpr.model_construct(
        kind="xor", left=FieldExpr(name="a"), right=FieldExpr(name="b"))
    with pytest.raises(UnsupportedCompositionBoundary):
        composition.render_qualified(bogus, "gate")
    with pytest.raises(UnsupportedCompositionBoundary):
        composition.render_qualified(object(), "gate")


def test_analyze_coupling_requires_resolved_component(v2_dir):
    spec = parse_composition(composition_value())
    resolved = resolve_bindings(spec, v2_dir)
    orphan = composition.CompositionUseCase(name="Orphan", steps=[
        composition.CompositionStep(component="stranger", operation="Open")])
    with pytest.raises(UnsupportedCompositionBoundary, match="stranger"):
        analyze_coupling(orphan, resolved)


def test_lint_composition_skips_partially_resolved_components(v2_dir):
    spec = parse_composition(composition_value())
    resolved = resolve_bindings(spec, v2_dir)
    partial = {"gate": resolved["gate"]}
    findings = lint_composition(spec, partial)
    assert findings == []
