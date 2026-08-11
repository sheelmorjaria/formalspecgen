import json
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from pipeline import scaffold_domain
from pipeline.jml_ast import (BinaryExpr, BooleanLiteral, FieldAccess, IntegerLiteral,
                              Parameter, ResultValue, UnaryExpr)
from pipeline.tla_ir import (BankingConcurrencyMetadata, BankingOperationIR,
                             BankingTlaModel, TLCConfig, preflight_tla,
                             render_banking_model, render_cfg)
from pipeline.transition_ir import (LocationIR, MethodTransitionIR, ParameterIR,
                                    TLARenderer, UnsupportedBoundaryError,
                                    assignment_from_equality, flatten_and)
from test_scaffold_domain import SPEC


def test_banking_operation_and_model_semantic_validators():
    with pytest.raises(ValidationError, match="cannot use effect"):
        BankingOperationIR(operation="deposit", guard_ids=[], effect_id="atomic_withdraw",
                           frame_ids=[], result_constrained=True, failure_preserves_frame=True)
    for field, values in (("guard_ids", ["positive_amount", "positive_amount"]),
                          ("frame_ids", ["receiver_balance", "receiver_balance"])):
        payload = dict(operation="deposit", guard_ids=["positive_amount"],
                       effect_id="atomic_deposit", frame_ids=["receiver_balance"],
                       result_constrained=True, failure_preserves_frame=True)
        payload[field] = values
        with pytest.raises(ValidationError, match="unique"):
            BankingOperationIR(**payload)
    with pytest.raises(ValidationError, match="non-empty unique"):
        BankingTlaModel(operations=[])
    with pytest.raises(ValidationError, match="non-empty unique"):
        BankingTlaModel(invariants=[])


def test_banking_concurrency_and_lock_protocol_rendering():
    metadata = BankingConcurrencyMetadata(
        abstraction="atomic_operations", linearization="method_atomic",
        lock_order="not_modeled", account_ids_immutable=True)
    with pytest.raises(ValidationError, match="abstraction does not match"):
        BankingTlaModel(abstraction="lock_protocol", concurrency=metadata)
    lock_metadata = BankingConcurrencyMetadata(
        abstraction="lock_protocol", linearization="ordered_account_locks",
        lock_order="ascending_immutable_account_id", account_ids_immutable=True)
    model = BankingTlaModel(abstraction="lock_protocol", concurrency=lock_metadata)
    source, cfg = render_banking_model(model)
    assert "AcquireSecond" in source and "OrderedLocking" in source
    assert "CHECK_DEADLOCK FALSE" not in cfg
    assert render_cfg(TLCConfig(invariants=["TypeOK"], check_deadlock=True)) == (
        "SPECIFICATION Spec\nINVARIANT TypeOK")


def test_preflight_reports_header_terminator_and_every_contamination_family():
    source = "public class C {}\n//@ ensures true;\n#[requires(true)]\nmethod M()\nSPECIFICATION Spec"
    errors = preflight_tla(source)
    assert any("header" in item for item in errors)
    assert any("terminator" in item for item in errors)
    assert len([item for item in errors if "forbidden" in item]) >= 5


def test_transition_frame_uniqueness_flatten_assignment_and_renderer_edges():
    duplicate = [LocationIR(field="balance"), LocationIR(field="balance")]
    with pytest.raises(ValidationError, match="frame locations"):
        MethodTransitionIR(name="m", parameters=[], guards=[], success_effects=[],
                           failure_effects=[], frame=duplicate, result_constrained=False)
    conjunction = BinaryExpr(kind="and", left=BooleanLiteral(value=True),
                             right=BinaryExpr(kind="and", left=BooleanLiteral(value=False),
                                              right=BooleanLiteral(value=True)))
    assert len(flatten_and(conjunction)) == 3
    equality = BinaryExpr(kind="eq", left=FieldAccess(field="balance"),
                          right=Parameter(name="amount"))
    assert assignment_from_equality(equality).target.field == "balance"
    assert assignment_from_equality(BooleanLiteral(value=True)) is None

    renderer = TLARenderer()
    assert renderer.render_expression(IntegerLiteral(value=3)) == "3"
    assert renderer.render_expression(BooleanLiteral(value=True)) == "TRUE"
    assert renderer.render_expression(UnaryExpr(kind="not", operand=BooleanLiteral(value=False))) == "~(FALSE)"
    with pytest.raises(UnsupportedBoundaryError, match="field 'other'"):
        renderer.render_expression(FieldAccess(field="other"))
    with pytest.raises(UnsupportedBoundaryError, match="unsafe identifier"):
        renderer.render_expression(Parameter(name="bad-name"))
    with pytest.raises(UnsupportedBoundaryError, match="success/failure"):
        renderer.render_expression(ResultValue())

    unsupported_unary = UnaryExpr.model_construct(
        kind="neg", operand=IntegerLiteral(value=1))
    with pytest.raises(UnsupportedBoundaryError, match="unary operation"):
        renderer.render_expression(unsupported_unary)
    unsupported_binary = BinaryExpr.model_construct(
        kind="implies", left=BooleanLiteral(value=True), right=BooleanLiteral(value=False))
    with pytest.raises(UnsupportedBoundaryError, match="must be lowered"):
        renderer.render_expression(unsupported_binary)
    with pytest.raises(UnsupportedBoundaryError, match="outside the supported"):
        renderer.render_expression(object())


def test_scaffolder_yaml_and_cli_paths(tmp_path, capsys):
    yaml_path = tmp_path / "domain.yaml"
    import yaml
    yaml_path.write_text(yaml.safe_dump(SPEC), encoding="utf-8")
    assert scaffold_domain.load_spec(yaml_path).module_name == "light_switch"

    with patch("sys.argv", ["scaffold", str(yaml_path), "--no-register"]), \
         patch.object(scaffold_domain, "scaffold_domain", return_value=[tmp_path / "x.py"]):
        scaffold_domain.main()
    output = capsys.readouterr().out
    assert "Scaffolded:" in output and "fails closed" in output


def test_scaffolder_yaml_missing_dependency_is_explicit(tmp_path):
    yaml_path = tmp_path / "domain.yaml"
    yaml_path.write_text("domain_name: X", encoding="utf-8")
    real_import = __import__

    def importing(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=importing):
        with pytest.raises(RuntimeError, match="requires PyYAML"):
            scaffold_domain.load_spec(yaml_path)
