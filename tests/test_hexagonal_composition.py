from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline.architecture import parse_architecture
from pipeline.composition import CompositionError, parse_composition
from pipeline.composition_render import (
    UnsupportedCompositionBoundary, build_composition_sources,
    render_external_adapter, render_external_port, verify_composition,
)


def artifact(port_overrides=None):
    port = {"id": "payments", "name": "PaymentGateway", "layer": "use_cases",
            "type": "interface", "external": True, "adapter": "StripePaymentGateway",
            "operations": [{"name": "charge",
                "parameters": [{"name": "amount", "type": "int"}],
                "returns": "boolean", "requires": ["amount > 0"],
                "ensures": ["\\result ==> amount > 0"], "assignable": []}]}
    port.update(port_overrides or {})
    return {"schema_version": 1, "system_name": "Orders",
        "architecture": {"name": "Orders", "description": "", "components": [
            {"id": "orders", "name": "Orders", "layer": "use_cases", "kind": "class",
             "operations": [], "dependencies": [{"target": "payments", "abstraction": True}]},
            port], "use_cases": []},
        "bindings": [{"component": "orders", "module_name": "orders"}],
        "use_cases": [{"name": "Submit", "steps": [
            {"component": "orders", "operation": "Submit"}]}]}


def test_external_type_alias_parses_as_contracted_port():
    spec = parse_composition(artifact())
    port = next(item for item in parse_architecture(spec.architecture).components
                if item.id == "payments")
    assert port.kind == "interface" and port.external
    assert port.operations[0].requires == ["amount > 0"]
    assert port.operations[0].ensures == ["\\result ==> amount > 0"]


def test_external_ports_fail_closed_without_valid_contract_shape():
    for override, message in [
        ({"operations": []}, "at least one operation"),
        ({"operations": [{"name": "charge", "parameters": [], "returns": "boolean",
                           "requires": [], "ensures": []}]}, "declare a contract"),
        ({"type": "class"}, "must be interfaces"),
        ({"kind": "class"}, "type and kind disagree"),
    ]:
        with pytest.raises(CompositionError, match=message):
            parse_composition(artifact(override))


def test_port_and_unverified_adapter_are_rendered_deterministically():
    spec = parse_composition(artifact())
    port = next(item for item in parse_architecture(spec.architecture).components
                if item.external)
    interface = render_external_port(port)
    adapter = render_external_adapter(port, "StripePaymentGateway")
    assert "public interface PaymentGateway" in interface
    assert "//@ requires amount > 0;" in interface
    assert "boolean charge(int amount);" in interface
    assert "implements PaymentGateway" in adapter
    assert "UNVERIFIED EXTERNAL BOUNDARY" in adapter
    assert "return false;" in adapter and "TODO: Implement external API call" in adapter


def test_external_renderer_default_name_return_shapes_and_invalid_identifier():
    value = artifact()
    del value["architecture"]["components"][1]["adapter"]
    value["architecture"]["components"][1]["operations"] = [
        {"name": "count", "parameters": [], "returns": "integer",
         "requires": ["true"], "ensures": ["\\result >= 0"]},
        {"name": "lookup", "parameters": [], "returns": "String",
         "requires": ["true"], "ensures": ["true"]},
        {"name": "notifyRemote", "parameters": [], "returns": "void",
         "requires": ["true"], "ensures": ["true"]},
    ]
    spec = parse_composition(value).model_copy(update={"bindings": [], "use_cases": []})
    sources = build_composition_sources(spec, {})
    adapter = sources["PaymentGatewayAdapter.java"]
    assert "return 0;" in adapter and "return null;" in adapter
    assert "void notifyRemote()" in adapter

    invalid = artifact({"adapter": "not-valid"})
    spec = parse_composition(invalid).model_copy(update={"bindings": [], "use_cases": []})
    with pytest.raises(UnsupportedCompositionBoundary, match="Java type identifier"):
        build_composition_sources(spec, {})


def test_composition_skips_adapter_but_proves_core_and_records_boundary():
    sources = {"Orders.java": "public class Orders {}",
               "PaymentGateway.java": "public interface PaymentGateway {}",
               "StripePaymentGateway.java": "public class StripePaymentGateway {}",
               "SubmitOrchestrator.java": "//@ requires ready;\npublic class SubmitOrchestrator {}"}
    calls = []
    def verified(paths, mode):
        calls.append((mode, {path.name for path in paths})); return 0, "proved"
    with patch("pipeline.composition_render.resolve_bindings", return_value={"orders": object()}), \
         patch("pipeline.composition_render.analyze_coupling", return_value={}), \
         patch("pipeline.composition_render.lint_composition", return_value=[]), \
         patch("pipeline.composition_render.build_composition_sources", return_value=sources), \
         patch("pipeline.composition_render.verify_files", side_effect=verified):
        result = verify_composition(artifact())
    assert result["claim"] == "SYSTEM_COMPOSITION_PROOF"
    assert result["unverified_boundaries"] == ["StripePaymentGateway"]
    assert result["verification_skips"]["StripePaymentGateway"] == \
        "Unverified external boundary"
    assert not result["external_io_safety_proved"]
    assert all("StripePaymentGateway.java" not in names for _, names in calls)
    assert all("PaymentGateway.java" in names for _, names in calls)


def test_external_step_injects_port_and_proves_bound_precondition():
    value = artifact()
    value["use_cases"] = [{"name": "ChargeOrder", "steps": [{
        "component": "payments", "operation": "charge",
        "arguments": {"amount": "amount"}}]}]
    spec = parse_composition(value).model_copy(update={"bindings": []})
    sources = build_composition_sources(spec, {})
    orchestrator = sources["ChargeOrderOrchestrator.java"]
    assert "private /*@ spec_public @*/ final PaymentGateway payments;" in orchestrator
    assert "ChargeOrderOrchestrator(PaymentGateway paymentsArg)" in orchestrator
    assert "//@ requires amount > 0;" in orchestrator
    assert "public void chargeOrder(int amount)" in orchestrator
    assert "payments.charge(amount);" in orchestrator
    assert "//@ assignable \\nothing;" in sources["PaymentGateway.java"]


def test_external_argument_bindings_fail_closed_on_missing_unsafe_and_conflicting_types():
    from pipeline.composition import UnsupportedCompositionBoundary, analyze_coupling, lint_composition
    value = artifact()
    value["use_cases"] = [{"name": "Charge", "steps": [{
        "component": "payments", "operation": "charge", "arguments": {}}]}]
    spec = parse_composition(value)
    architecture = parse_architecture(spec.architecture)
    findings = lint_composition(spec, {})
    assert any(item["code"] == "composition-port-argument-mismatch" for item in findings)
    with pytest.raises(UnsupportedCompositionBoundary, match="exact argument"):
        analyze_coupling(spec.use_cases[0], {}, architecture)

    value["use_cases"][0]["steps"][0]["arguments"] = {"amount": "amount + 1"}
    spec = parse_composition(value)
    assert any(item["code"] == "composition-unsafe-port-argument"
               for item in lint_composition(spec, {}))
    with pytest.raises(UnsupportedCompositionBoundary, match="unsupported Port argument"):
        analyze_coupling(spec.use_cases[0], {}, parse_architecture(spec.architecture))

    value = artifact()
    port = value["architecture"]["components"][1]
    labels = {**port, "id": "labels", "name": "LabelGateway", "adapter": "LabelAdapter",
              "operations": [{"name": "label",
        "parameters": [{"name": "text", "type": "String"}], "returns": "boolean",
        "requires": ["text != null"], "ensures": ["true"]}]}
    value["architecture"]["components"].append(labels)
    value["use_cases"] = [{"name": "Conflict", "steps": [
        {"component": "payments", "operation": "charge", "arguments": {"amount": "input"}},
        {"component": "labels", "operation": "label", "arguments": {"text": "input"}}]}]
    spec = parse_composition(value)
    with pytest.raises(UnsupportedCompositionBoundary, match="conflicting Port types"):
        analyze_coupling(spec.use_cases[0], {}, parse_architecture(spec.architecture))


def test_unknown_port_internal_arguments_and_literal_binding_paths():
    from pipeline.composition import UnsupportedCompositionBoundary, analyze_coupling, lint_composition
    value = artifact()
    value["use_cases"] = [{"name": "Unknown", "steps": [{
        "component": "payments", "operation": "refund", "arguments": {}}]}]
    spec = parse_composition(value)
    architecture = parse_architecture(spec.architecture)
    assert any(item["code"] == "composition-unknown-port-operation"
               for item in lint_composition(spec, {}))
    with pytest.raises(UnsupportedCompositionBoundary, match="has no operation"):
        analyze_coupling(spec.use_cases[0], {}, architecture)

    value = artifact()
    value["use_cases"][0]["steps"][0]["arguments"] = {"unexpected": "1"}
    spec = parse_composition(value)
    reviewed = SimpleNamespace(operations=[SimpleNamespace(
        name="Submit", return_type="void", guards=[])])
    assert any(item["code"] == "composition-internal-arguments"
               for item in lint_composition(spec, {"orders": reviewed}))

    value = artifact()
    value["use_cases"] = [{"name": "Literal", "steps": [{
        "component": "payments", "operation": "charge", "arguments": {"amount": "5"}}]}]
    spec = parse_composition(value)
    coupling = analyze_coupling(
        spec.use_cases[0], {}, parse_architecture(spec.architecture))
    assert coupling["caller_preconditions"] == ["5 > 0"]
    assert coupling["orchestrator_parameters"] == {}


def test_composition_reports_adapter_rendering_boundary():
    with patch("pipeline.composition_render.resolve_bindings", return_value={"orders": object()}), \
         patch("pipeline.composition_render.analyze_coupling", return_value={}), \
         patch("pipeline.composition_render.lint_composition", return_value=[]), \
         patch("pipeline.composition_render.build_composition_sources",
               side_effect=UnsupportedCompositionBoundary("bad adapter")):
        result = verify_composition(artifact())
    assert result["status"] == "UNSUPPORTED_BOUNDARY"
    assert result["claim"] == "NO_PROOF"
