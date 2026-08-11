import json

import pytest
from pydantic import ValidationError

from pipeline.domain_generator import compile_domain_spec, elicit_domain_questions
from pipeline.domains import inventory_extract as inventory
from pipeline.domains.inventory import InventoryOperationIR, InventoryTlaModel
from pipeline.extract_tla_ir import UnsupportedJmlSemantics
from pipeline.jml_ast import parse_jml_expression
from pipeline.transition_ir import MethodTransitionIR
from test_inventory_domain import INVENTORY_JML


FIELDS = {"stock", "reserved"}
PARAMS = {"amount"}


def expr(source):
    return parse_jml_expression(source, fields=FIELDS, parameters=PARAMS)


def test_inventory_guard_matchers_cover_nested_reversed_and_unknown_shapes():
    capacity = expr("amount <= 4 - \\old(stock)")
    nested = expr("amount > 0 && amount <= \\old(stock) - \\old(reserved)")
    reserved = expr("amount <= reserved")
    assert inventory._contains_capacity(capacity, "stock")
    assert inventory._contains_available_stock(nested)
    assert inventory._contains_reserved_stock(reserved)
    assert not inventory._contains_capacity(expr("amount > 0"), "stock")
    assert not inventory._contains_available_stock(expr("amount <= stock"))
    assert not inventory._contains_reserved_stock(expr("stock >= 0"))


def test_inventory_requires_complete_api_and_supported_abstraction():
    with pytest.raises(UnsupportedJmlSemantics, match="atomic_operations"):
        inventory.extract_inventory_model(INVENTORY_JML, "", "lock_protocol")
    incomplete = INVENTORY_JML.replace("public boolean release(long amount)",
                                       "public boolean remove(long amount)")
    with pytest.raises(UnsupportedJmlSemantics, match="requires addStock"):
        inventory.extract_inventory_model(incomplete, "")


def test_inventory_missing_guards_and_failure_preservation_fail_typed_gate():
    missing_positive = INVENTORY_JML.replace("//@ requires amount > 0;", "", 1)
    model, findings = inventory.extract_inventory_model(missing_positive, "")
    assert any(item["code"] == "missing_guard" for item in findings)
    assert "positive_amount" not in model.operations[0].guard_ids

    missing_failure = INVENTORY_JML.replace(
        "//@ ensures !\\result ==> stock == \\old(stock);", "", 1)
    model, findings = inventory.extract_inventory_model(missing_failure, "")
    assert any(item["code"] == "failure_changes_state" for item in findings)
    assert model.operations[0].failure_preserves_frame is False


def test_inventory_model_rejects_operation_transition_and_amount_drift():
    model, _ = inventory.extract_inventory_model(INVENTORY_JML, "")
    payload = model.model_dump()
    with pytest.raises(ValidationError, match="operations must"):
        InventoryTlaModel(**{**payload, "operations": list(reversed(payload["operations"]))})
    with pytest.raises(ValidationError, match="transitions must"):
        InventoryTlaModel(**{**payload, "transitions": list(reversed(payload["transitions"]))})
    with pytest.raises(ValidationError, match="amounts must"):
        InventoryTlaModel(**{**payload, "amounts": [1, 1]})
    with pytest.raises(ValidationError, match="amounts must"):
        InventoryTlaModel(**{**payload, "amounts": [5]})


def test_domain_question_elicitation_rejects_empty_idea_before_llm():
    calls = []
    with pytest.raises(ValueError, match="idea is required"):
        elicit_domain_questions("  ", lambda *args: calls.append(args))
    assert calls == []


def test_domain_compilation_includes_only_answered_clarifications():
    proposed = {
        "domain_name": "Door", "module_name": "door",
        "state_variables": [{"name": "state", "type": "int", "bound": [0, 2]}],
        "operations": [{"name": "openDoor", "guards": ["is_closed"],
                        "effect": "set_open", "frame": ["state"],
                        "ast_pattern": "state == 1"}],
        "tlc_invariants": ["TypeOK"],
    }
    captured = {}

    def chat(messages, model, temperature):
        captured["prompt"] = messages[-1]["content"]
        return json.dumps(proposed), "domain-model", {"total_tokens": 4}

    questions = [
        {"id": "required", "category": "bounds", "question": "State bound?", "required": True},
        {"id": "optional", "category": "other", "question": "Colour?", "required": False},
    ]
    spec, yaml_text, used, usage = compile_domain_spec(
        "A door", questions, [{"id": "required", "answer": "0 to 2"}], chat)
    assert "State bound?" in captured["prompt"] and "Colour?" not in captured["prompt"]
    assert spec.module_name == "door" and "module_name: door" in yaml_text
    assert used == "domain-model" and usage["total_tokens"] == 4


def test_inventory_operation_schema_rejects_unreviewed_semantics():
    with pytest.raises(ValidationError):
        InventoryOperationIR(operation="addStock", guard_ids=["invented"],
                             effect_id="increase_stock", frame_ids=["product_stock"],
                             result_constrained=True, failure_preserves_frame=True)
