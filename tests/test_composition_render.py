# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic composition rendering, ESC verification, and impact re-verification."""
import json
from unittest.mock import patch

import pytest

from pipeline import composition_render
from pipeline.composition import parse_composition, resolve_bindings


def reviewed_spec(domain="Gate", module="gate", *, noop=False):
    operations = [
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
            "guards": [
                {
                    "id": "g1",
                    "expression": {
                        "kind": "eq",
                        "left": {"kind": "field", "name": "door"},
                        "right": {"kind": "integer", "value": 1},
                    },
                }
            ],
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
    ]
    if noop:
        operations.append(
            {
                "name": "Idle",
                "return_type": "void",
                "failure_semantics": "unavailable",
                "guards": [],
                "effects": [],
                "frame": [],
                "exception_type": None,
                "exception_trigger": None,
            })
    return {
        "schema_version": 2,
        "review_status": "reviewed",
        "domain_name": domain,
        "module_name": module,
        "state_variables": [
            {"kind": "int", "name": "door", "bound": [0, 1], "initial": 0}
        ],
        "operations": operations,
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
        "accepted_candidate_sha256": "a" * 64,
        "accepted_evidence_sha256": "b" * 64,
    }


def composition_value():
    return {
        "system_name": "GateSystem",
        "architecture": {
            "name": "GateSystem",
            "description": "gate plus control panel",
            "components": [
                {"id": "gate", "name": "Gate", "layer": "entities", "kind": "class",
                 "operations": [], "dependencies": []},
                {"id": "panel", "name": "Panel", "layer": "use_cases", "kind": "class",
                 "operations": [], "dependencies": [{"target": "gate", "abstraction": True}]},
            ],
            "use_cases": [],
        },
        "bindings": [
            {"component": "gate", "module_name": "gate"},
            {"component": "panel", "module_name": "panel"},
        ],
        "use_cases": [
            {"name": "OpenGate", "steps": [{"component": "gate", "operation": "Open"}]},
            {"name": "PanelOpensGate", "steps": [
                {"component": "panel", "operation": "Open"}]},
        ],
    }


@pytest.fixture()
def v2_dir(tmp_path):
    directory = tmp_path / "v2"
    directory.mkdir()
    (directory / "gate.json").write_text(
        json.dumps(reviewed_spec()), encoding="utf-8")
    (directory / "panel.json").write_text(
        json.dumps(reviewed_spec(domain="Panel", module="panel")), encoding="utf-8")
    return directory


def _resolved(v2_dir):
    return resolve_bindings(parse_composition(composition_value()), v2_dir)


def test_render_interface_is_abstraction_surface_only(v2_dir):
    resolved = _resolved(v2_dir)
    source = composition_render.render_interface(resolved["gate"])
    assert "public interface GateAPI {" in source
    assert "public /*@ pure @*/ int getDoor();" in source
    assert "void open();" in source
    assert "reviewed module 'gate'" in source
    assert "//@ requires" not in source and "//@ ensures" not in source


def test_render_orchestrator_derives_contract_from_reviewed_spec(v2_dir):
    resolved = _resolved(v2_dir)
    spec = parse_composition(composition_value())
    source = composition_render.render_orchestrator(spec.use_cases[0], resolved)
    assert "public class OpenGateOrchestrator {" in source
    assert "private /*@ spec_public @*/ final Gate gate;" in source
    assert "    //@ requires gateArg != null;" in source
    assert "    //@ ensures this.gate == gateArg;" in source
    assert "    //@ requires gate.door == 0;" in source
    assert "    //@ assignable gate.door;" in source
    assert "    //@ ensures gate.door == 1;" in source
    assert "        gate.open();" in source


def test_build_composition_sources(v2_dir):
    spec = parse_composition(composition_value())
    sources = composition_render.build_composition_sources(spec, _resolved(v2_dir))
    assert set(sources) == {"Gate.java", "GateAPI.java", "Panel.java", "PanelAPI.java",
                            "OpenGateOrchestrator.java", "PanelOpensGateOrchestrator.java"}
    assert "public class Gate {" in sources["Gate.java"]


def test_verify_composition_statuses(v2_dir):
    value = composition_value()
    with patch.object(composition_render, "verify_files",
                      return_value=(1, "error: bad spec")):
        result = composition_render.verify_composition(value, v2_dir)
    assert result["status"] == "CHECK_FAILED" and result["claim"] == "NO_PROOF"

    with patch.object(composition_render, "verify_files",
                      side_effect=[(0, "check ok"), (0, "esc ok")]) as run:
        result = composition_render.verify_composition(value, v2_dir)
    assert result["status"] == "COMPOSITION_VERIFIED"
    assert result["claim"] == "SCOPED_COMPOSITION_PROOF"
    assert result["scope"] == "single_threaded_atomic_contract_composition"
    assert result["concurrent_linearizability_proved"] is False
    assert [call.kwargs["mode"] for call in run.call_args_list] == ["check", "esc"]
    assert result["coupling"][0]["use_case"] == "OpenGate"

    with patch.object(composition_render, "verify_files",
                      side_effect=[(0, "check ok"), (6, "error: failed VC")]):
        result = composition_render.verify_composition(value, v2_dir)
    assert result["status"] == "COMPOSITION_VERIFY_FAILED"
    assert result["claim"] == "NO_PROOF" and result["diagnostics"] == []

    with patch.object(composition_render, "verify_files",
                      side_effect=[(0, "check ok"), (0, "Not yet supported feature: X")]):
        result = composition_render.verify_composition(value, v2_dir)
    assert result["status"] == "VACUOUS_COMPOSITION"

    with patch.object(composition_render, "verify_files",
                      return_value=(0, "check ok")) as run:
        result = composition_render.verify_composition(value, v2_dir, run_esc=False)
    assert result["status"] == "COMPOSITION_CHECKED"
    assert result["claim"] == "STATIC_CHECK" and run.call_count == 1


def test_verify_composition_rejects_openjml_vacuity_warning(v2_dir):
    with patch.object(composition_render, "verify_files", side_effect=[
            (0, "check ok"), (0, "warning: Precondition is always false")]):
        result = composition_render.verify_composition(composition_value(), v2_dir)
    assert result["status"] == "VACUOUS_COMPOSITION"
    assert result["claim"] == "NO_PROOF"


def test_verify_composition_fails_closed_early(v2_dir, tmp_path):
    result = composition_render.verify_composition(
        composition_value(), tmp_path / "empty")
    assert result["status"] == "RESOLUTION_FAILED" and result["claim"] == "NO_PROOF"

    inverted = composition_value()
    inverted["architecture"]["components"][0]["dependencies"] = [
        {"target": "panel", "abstraction": True}]
    inverted["architecture"]["components"][1]["layer"] = "infrastructure"
    inverted["architecture"]["components"][1]["dependencies"] = []
    result = composition_render.verify_composition(inverted, v2_dir)
    assert result["status"] == "COMPOSITION_LINT_FAILED"
    assert any(item["code"] == "dependency-inversion"
               for item in result["findings"])

    boolean = composition_value()
    boolean["use_cases"][1]["steps"][0]["operation"] = "TryToggle"
    boolean["bindings"][1] = {"component": "panel", "module_name": "gate"}
    result = composition_render.verify_composition(boolean, v2_dir)
    assert result["status"] == "UNSUPPORTED_BOUNDARY" and "TryToggle" in result["message"]


def test_verify_composition_vacuous_without_orchestrator_obligations(tmp_path):
    directory = tmp_path / "v2"
    directory.mkdir()
    (directory / "gate.json").write_text(
        json.dumps(reviewed_spec(noop=True)), encoding="utf-8")
    (directory / "panel.json").write_text(
        json.dumps(reviewed_spec(domain="Panel", module="panel", noop=True)),
        encoding="utf-8")
    value = composition_value()
    value["use_cases"] = [
        {"name": "Idle", "steps": [{"component": "gate", "operation": "Idle"}]},
        {"name": "PanelIdles", "steps": [{"component": "panel", "operation": "Idle"}]},
    ]
    with patch.object(composition_render, "verify_files",
                      side_effect=[(0, "check ok"), (0, "esc ok")]):
        result = composition_render.verify_composition(value, directory)
    assert result["status"] == "VACUOUS_COMPOSITION"
    assert "caller precondition" in result["message"]


def test_reverify_composition_reports_impact(v2_dir):
    with patch.object(composition_render, "verify_files",
                      side_effect=[(0, "check ok"), (0, "esc ok")]):
        result = composition_render.reverify_composition(
            composition_value(), "gate", v2_dir)
    assert result["status"] == "REVERIFIED"
    assert result["changed_module"] == "gate"
    assert result["impacted_components"] == ["gate", "panel"]
    assert result["impacted_use_cases"] == ["OpenGate", "PanelOpensGate"]
    assert result["concurrent_linearizability_proved"] is False

    with patch.object(composition_render, "verify_files",
                      side_effect=[(0, "check ok"), (6, "error: broken coupling")]):
        result = composition_render.reverify_composition(
            composition_value(), "gate", v2_dir)
    assert result["status"] == "REVERIFICATION_FAILED"
    assert result["composition_status"] == "COMPOSITION_VERIFY_FAILED"

    result = composition_render.reverify_composition(
        composition_value(), "unrelated_module", v2_dir)
    assert result["status"] == "NOT_IMPACTED"


def test_reverify_composition_resolution_failure_and_edge_walk(v2_dir, tmp_path):
    result = composition_render.reverify_composition(
        composition_value(), "gate", tmp_path / "empty")
    assert result["status"] == "RESOLUTION_FAILED" and result["claim"] == "NO_PROOF"

    value = composition_value()
    # A diamond (journal -> panel/audit -> gate) walks an already-impacted
    # dependent, and the unbound "logs" target exercises the skipped edge.
    value["architecture"]["components"].extend([
        {"id": "audit", "name": "Audit", "layer": "use_cases", "kind": "class",
         "operations": [], "dependencies": [{"target": "gate", "abstraction": True}]},
        {"id": "journal", "name": "Journal", "layer": "adapters", "kind": "class",
         "operations": [], "dependencies": [
             {"target": "panel", "abstraction": True},
             {"target": "audit", "abstraction": True}]},
        {"id": "logs", "name": "AuditLog", "layer": "entities", "kind": "class",
         "operations": [], "dependencies": []},
    ])
    value["architecture"]["components"][1]["dependencies"].append(
        {"target": "logs", "abstraction": True})
    value["bindings"].extend([
        {"component": "audit", "module_name": "gate"},
        {"component": "journal", "module_name": "gate"},
    ])
    with patch.object(composition_render, "verify_files",
                      side_effect=[(0, "check ok"), (0, "esc ok")]):
        result = composition_render.reverify_composition(value, "gate", v2_dir)
    assert result["status"] == "REVERIFIED"
    assert result["impacted_components"] == ["audit", "gate", "journal", "panel"]


def test_build_sources_dedupes_shared_domains(v2_dir):
    shared = composition_value()
    shared["bindings"][1] = {"component": "panel", "module_name": "gate"}
    spec = parse_composition(shared)
    sources = composition_render.build_composition_sources(
        spec, resolve_bindings(spec, v2_dir))
    assert "Panel.java" not in sources and "PanelAPI.java" not in sources
    assert "Gate.java" in sources and "GateAPI.java" in sources
    assert set(sources) == {"Gate.java", "GateAPI.java",
                            "OpenGateOrchestrator.java",
                            "PanelOpensGateOrchestrator.java"}


def test_render_verified_class_synthesizes_reviewed_bodies(v2_dir):
    resolved = _resolved(v2_dir)
    source = composition_render.render_verified_class(resolved["gate"])
    assert "public class Gate {" in source
    # void op: the reviewed effect becomes the deterministic body
    assert "public void open() {" in source
    assert "        this.door = 1;" in source
    # boolean op: guard check, stutter path, pre-captured simultaneous effect
    assert "public boolean tryToggle() {" in source
    assert "if (!(this.door == 1)) {" in source
    assert "final int pre_door = this.door;" in source
    assert "this.door = pre_door;" in source
    assert "return true;" in source and "return false;" in source


def test_render_verified_class_fails_closed_on_exception_semantics(v2_dir):
    resolved = _resolved(v2_dir)
    spec = resolved["gate"].model_dump(mode="json")
    spec["operations"].append({
        "name": "ForceOpen", "return_type": "void",
        "failure_semantics": "exception",
        "guards": [], "effects": [], "frame": [],
        "exception_type": "IllegalState",
        "exception_trigger": {"kind": "boolean", "value": True}})
    reviewed = composition_render.ReviewedDomainSpecV2.model_validate(spec)
    with pytest.raises(composition_render.UnsupportedCompositionBoundary):
        composition_render.render_verified_class(reviewed)


def test_body_expression_full_subset_and_fail_closed():
    from pipeline.domain_v2 import (
        BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr)
    node = BinaryExpr(kind="and",
                      left=NotExpr(expression=FieldExpr(name="door")),
                      right=OldExpr(expression=FieldExpr(name="door")))
    assert composition_render._body_expression(
        node, {"door": "pre_door"}) == "(!(pre_door) && pre_door)"
    assert composition_render._body_expression(IntegerExpr(value=3), {}) == "3"
    assert composition_render._body_expression(
        BooleanExpr(value=False), {}) == "false"
    bogus = BinaryExpr.model_construct(
        kind="xor", left=FieldExpr(name="a"), right=FieldExpr(name="b"))
    with pytest.raises(composition_render.UnsupportedCompositionBoundary):
        composition_render._body_expression(bogus, {"a": "x", "b": "y"})
    with pytest.raises(composition_render.UnsupportedCompositionBoundary):
        composition_render._body_expression(object(), {})
    with pytest.raises(composition_render.UnsupportedCompositionBoundary):
        composition_render._body_expression(FieldExpr(name="ghost"), {})


def test_has_operation_obligations_ignores_constructor_clauses():
    constructor_only = (
        "    //@ requires gateArg != null;\n"
        "    //@ ensures this.gate == gateArg;\n")
    assert not composition_render._has_operation_obligations(constructor_only)
    assert composition_render._has_operation_obligations(
        constructor_only + "    //@ requires gate.door == 0;\n")
    assert composition_render._has_operation_obligations(
        constructor_only + "    //@ ensures gate.door == 1;\n")


def test_bindings_can_require_verified_promotion_signatures(v2_dir, monkeypatch):
    monkeypatch.setenv("FORMALSPECGEN_REQUIRE_SIGNATURES", "1")
    with patch("pipeline.composition.verify_artifact_signature",
               return_value={"status": "SIGNATURE_MISSING"}):
        with pytest.raises(Exception, match="Cryptographic signature verification failed"):
            resolve_bindings(parse_composition(composition_value()), v2_dir)
