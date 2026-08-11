import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import orchestrator, spec_lint
from pipeline.domains.inventory import InventoryTlaModel
from pipeline.domains.inventory_render import render_inventory
from pipeline.domains.train_crossing import TrainRoadCrossingTlaModel
from pipeline.domains.train_crossing_render import render_train_crossing
from pipeline.jml_ast import (BinaryExpr, BooleanLiteral, FieldAccess,
                              JmlExpressionSyntaxError, UnaryExpr,
                              parse_jml_expression)
from pipeline.llm import LLMError
from pipeline.schemas import VC


def test_jml_parser_literals_receivers_unary_and_right_associativity():
    assert parse_jml_expression("42L").value == 42
    assert parse_jml_expression("true") == BooleanLiteral(value=True)
    field = parse_jml_expression("source.balance", fields={"balance"})
    assert field == FieldAccess(receiver="source", field="balance")
    unary = parse_jml_expression("!-amount", parameters={"amount"})
    assert isinstance(unary, UnaryExpr) and unary.kind == "not" and unary.operand.kind == "neg"
    implied = parse_jml_expression("a ==> b ==> c", parameters={"a", "b", "c"})
    assert isinstance(implied, BinaryExpr) and implied.right.kind == "implies"
    grouped = parse_jml_expression("(a + 1) * 2", parameters={"a"})
    assert grouped.kind == "mul" and grouped.left.kind == "add"


@pytest.mark.parametrize("source,reason", [
    ("", "empty expression"),
    ("1 +", "expected expression"),
    ("(1 + 2", "expected ')'"),
    ("receiver.", "expected field name"),
    ("1 2", "unexpected token"),
    ("@", "unsupported token"),
])
def test_jml_parser_reports_precise_fail_closed_errors(source, reason):
    with pytest.raises(JmlExpressionSyntaxError, match=re.escape(reason)):
        parse_jml_expression(source, fields={"balance"}, parameters={"receiver"})


def test_spec_lint_helpers_preserve_partial_parentheses_and_old_equivalence():
    assert spec_lint._strip_outer_parens("((a))") == "a"
    assert spec_lint._strip_outer_parens("(a) && (b)") == "(a) && (b)"
    assert spec_lint._contract_expr(r"(amount <= \old(balance))") == "amount<=balance"
    assert spec_lint._boolean_feasibility_excluded("//@ ensures true;") == []
    contracts = r"""//@ requires amount > 0;
//@ requires amount <= balance;
//@ ensures \result <==> (amount > 0 && amount <= \old(balance));
"""
    assert spec_lint._boolean_feasibility_excluded(contracts) == ["amount>0", "amount<=balance"]


def test_domain_renderers_reject_incomplete_semantic_sets():
    inventory = InventoryTlaModel.model_construct(operations=[], transitions=[])
    with pytest.raises(ValueError, match="inventory effect set"):
        render_inventory(inventory)
    crossing = TrainRoadCrossingTlaModel.model_construct(operations=[], transitions=[])
    with pytest.raises(ValueError, match="incomplete train-crossing"):
        render_train_crossing(crossing)


def test_orchestrator_repair_same_provider_does_not_silently_fallback():
    with (patch.object(orchestrator, "_chat_fn", return_value=object()),
          patch.object(orchestrator, "glm_repair_spec", side_effect=LLMError("API", "down"))):
        with pytest.raises(LLMError):
            orchestrator._repair("old", "error", "nl", None, "glm", "glm")


def test_check_attempt_preserves_parsed_javac_diagnostic(tmp_path):
    compiled = SimpleNamespace(returncode=1, stdout="", stderr="A.java:2: error: bad symbol")
    parsed = [VC("A.java", 2, "error", detail="bad symbol")]
    with (patch.object(orchestrator.subprocess, "run", return_value=compiled),
          patch.object(orchestrator, "parse_check", return_value=parsed)):
        result = orchestrator._check_attempt(tmp_path, "public class A {}", "Draft")
    assert result[2] == parsed


def test_orchestrator_cli_forwards_budget_and_provider_options(tmp_path):
    argv = ["orchestrator", "counter", "--provider", "ollama", "--fallback-provider", "glm",
            "--max-attempts", "3", "--resample-budget", "2", "--feedback-budget", "1",
            "--out", str(tmp_path)]
    with patch("sys.argv", argv), patch.object(orchestrator, "run") as run:
        orchestrator.main()
    run.assert_called_once_with("counter", provider="ollama", fallback_provider="glm",
                                model=None, max_attempts=3, out_dir=str(tmp_path),
                                resample_budget=2, feedback_budget=1)
