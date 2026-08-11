from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import elicit, extract_tla_ir as extraction, tla_backend
from pipeline.llm import LLMError
from pipeline.tla_ir import BankingConcurrencyMetadata, BankingOperationIR
from test_tla_banking import ATOMIC_CLARIFICATIONS, BANKING_JML


def test_elicitation_rejects_empty_requirement_and_non_array_json():
    calls = []
    with pytest.raises(ValueError, match="nl_text is required"):
        elicit.extract_ambiguities(" ", lambda *args: calls.append(args))
    assert calls == []
    for value in ({"not_questions": []}, "text", 3):
        with pytest.raises(LLMError, match="questions array"):
            elicit.normalize_questions(value)


def test_question_normalization_strings_duplicates_ids_categories_and_lengths():
    long = "x" * (elicit.MAX_QUESTION_LENGTH + 20)
    questions = elicit.normalize_questions([
        "Plain question?",
        {"id": "same", "category": "BOUNDS", "question": long, "required": False},
        {"id": "same", "category": "invented", "question": "Second?"},
        {"question": "   "},
        17,
        {"question": "plain   QUESTION?"},
    ])
    assert questions[0]["id"] == "q1"
    assert len(questions[1]["question"]) == elicit.MAX_QUESTION_LENGTH
    assert questions[1]["required"] is False and questions[1]["category"] == "bounds"
    assert questions[2]["id"] == "same_" and questions[2]["category"] == "other"
    assert len(questions) == 3


def test_augment_ignores_unknown_optional_and_non_dict_answers():
    questions = [{"id": "q1", "question": "Optional?", "required": False}]
    enriched = elicit.augment_spec("Requirement", questions,
                                   ["bad", {"id": "unknown", "answer": "ignored"}])
    assert enriched.endswith("Clarifications (human-provided and authoritative):")
    assert "ignored" not in enriched


def test_banking_parameter_clause_and_method_shape_rejections():
    assert extraction._parameters("") == []
    params = extraction._parameters("long amount, Account destination, boolean urgent")
    assert [(item.name, item.type) for item in params] == [("amount", "long"), ("urgent", "boolean")]
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="parameter declaration"):
        extraction._parameters("int[] values")
    missing = BANKING_JML.replace("public boolean transfer", "public boolean move")
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="Missing reviewed banking methods"):
        extraction.extract_banking_model(missing, ATOMIC_CLARIFICATIONS)


def test_transition_extraction_rejects_unreviewed_clauses_and_assignable_shapes():
    base = """//@ requires amount > 0;
//@ assignable balance;
//@ ensures \\result <==> amount > 0;
//@ ensures \\result ==> balance == \\old(balance) + amount;
//@ ensures !\\result ==> balance == \\old(balance);
"""
    transition = extraction.extract_method_transition_ir(
        "deposit", "boolean", "long amount", base, {"balance"})
    assert transition.result_constrained and len(transition.success_effects) == 1
    nothing = base.replace("assignable balance", r"assignable \nothing")
    assert extraction.extract_method_transition_ir(
        "deposit", "boolean", "long amount", nothing, {"balance"}).frame == []
    unsupported = base.replace("assignable balance", "assignable balance[*]")
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="assignable location"):
        extraction.extract_method_transition_ir(
            "deposit", "boolean", "long amount", unsupported, {"balance"})
    raw = base.replace(r"\result ==> balance == \old(balance) + amount",
                       r"\result ==> amount > 0")
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="result-guarded"):
        extraction.extract_method_transition_ir("deposit", "boolean", "long amount", raw, {"balance"})


def test_transition_extraction_rejects_parser_visitor_and_void_effect_boundaries():
    malformed = "//@ requires amount + ;\n"
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="Unsupported JML expression"):
        extraction.extract_method_transition_ir(
            "deposit", "void", "long amount", malformed, {"balance"})

    unguarded_boolean = "//@ ensures amount > 0 ==> balance == amount;\n"
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="no reviewed transition lowering"):
        extraction.extract_method_transition_ir(
            "deposit", "boolean", "long amount", unguarded_boolean, {"balance"})

    invalid_void = "//@ ensures amount > 0;\n"
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="unconditional postcondition"):
        extraction.extract_method_transition_ir(
            "deposit", "void", "long amount", invalid_void, {"balance"})

    unknown_field = "//@ requires limit > 0;\n"
    with pytest.raises(extraction.UnsupportedJmlSemantics, match=r"no reviewed TLA\+ state-variable"):
        extraction.extract_method_transition_ir(
            "deposit", "void", "", unknown_field, {"limit"})


def test_void_transition_compiles_conjoined_assignments_and_object_frames():
    contracts = r"""//@ ensures balance == \old(balance) + amount && audit == \old(audit) + 1;
//@ assignable balance, account.audit, \nothing;
"""
    transition = extraction.extract_method_transition_ir(
        "deposit", "void", "long amount, Account account", contracts,
        {"balance", "audit"}, {"balance": "balances", "audit": "audits"})
    assert len(transition.success_effects) == 2
    assert [(item.receiver, item.field) for item in transition.frame] == [
        ("this", "balance"), ("account", "audit")]


def test_reviewed_operation_mapper_fails_closed_and_records_optional_guards():
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="deposit effect"):
        extraction._extract_operation("deposit", "boolean", "//@ ensures \\result;\n")
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="withdraw effect"):
        extraction._extract_operation("withdraw", "boolean", "//@ ensures \\result;\n")
    with pytest.raises(extraction.UnsupportedJmlSemantics, match="transfer debit/credit"):
        extraction._extract_operation("transfer", "boolean", "//@ ensures \\result;\n")

    deposit = extraction._extract_operation("deposit", "boolean", r"""//@ requires amount > 0;
//@ requires amount <= 100L - \old(balance);
//@ assignable balance;
//@ ensures \result ==> balance == \old(balance) + amount;
//@ ensures !\result ==> balance == \old(balance);
""")
    assert deposit.guard_ids == ["positive_amount", "destination_has_capacity"]

    withdraw = extraction._extract_operation("withdraw", "boolean", r"""//@ signals (IllegalArgumentException e) amount <= 0;
//@ requires amount <= balance;
//@ assignable balance;
//@ ensures \result ==> balance == \old(balance) - amount;
//@ ensures !\result ==> balance == \old(balance);
""")
    assert withdraw.guard_ids == ["positive_amount", "source_has_funds"]

    transfer = extraction._extract_operation("transfer", "boolean", r"""//@ requires amount > 0;
//@ requires source != destination;
//@ requires amount <= source.balance;
//@ requires \old(destination.balance) + amount <= 100L;
//@ assignable source.balance, destination.balance;
//@ ensures \result ==> source.balance == \old(source.balance) - amount && destination.balance == \old(destination.balance) + amount;
//@ ensures !\result ==> source.balance == \old(source.balance) && destination.balance == \old(destination.balance);
""")
    assert transfer.guard_ids == ["positive_amount", "source_has_funds",
                                  "destination_has_capacity", "distinct_accounts"]
    assert transfer.frame_ids == ["source_balance", "destination_balance"]


def test_consistency_reports_every_reviewed_failure_and_unsafe_lock_order():
    operations = [
        BankingOperationIR(operation="deposit", guard_ids=[], effect_id="atomic_deposit",
                           frame_ids=[], result_constrained=False, failure_preserves_frame=False),
        BankingOperationIR(operation="withdraw", guard_ids=[], effect_id="atomic_withdraw",
                           frame_ids=[], result_constrained=False, failure_preserves_frame=False),
        BankingOperationIR(operation="transfer", guard_ids=[], effect_id="atomic_transfer",
                           frame_ids=[], result_constrained=False, failure_preserves_frame=False),
    ]
    metadata = BankingConcurrencyMetadata.model_construct(
        abstraction="lock_protocol", linearization="ordered_account_locks",
        lock_order="not_modeled", account_ids_immutable=False)
    findings = extraction.check_consistency(operations, metadata)
    codes = {item["code"] for item in findings}
    assert {"unconstrained_result", "failure_changes_state", "frame_mismatch",
            "missing_guard", "unsafe_lock_order"} <= codes


def test_tla_cfg_unknown_shapes_comments_names_and_parse_error():
    cfg = r"""\* comment
INIT Init
NEXT Next
INVARIANTS
TypeOK(x)
PROPERTY Module!Live
"""
    normalized = tla_backend.normalize_cfg(cfg)
    assert "INVARIANT TypeOK(x)" in normalized  # preserved for TLC to reject authoritatively
    assert "PROPERTY Module!Live" in normalized
    assert tla_backend._cfg_names("- TypeOK, Safe") == ["TypeOK", "Safe"]
    assert tla_backend._cfg_names("Bad(x)") == []
    source = "Init == TRUE\nNext == \\/ TRUE\n===="
    assert tla_backend.check_tla(source, "INIT Init\nNEXT Next")["status"] == "PARSE_ERROR"


def test_tla_without_deadlock_directive_does_not_add_flag():
    module = """---- MODULE M ----
VARIABLE x
Init == x = 0
Next == x' = x
===="""
    completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
    with patch.object(tla_backend.subprocess, "run", return_value=completed) as run:
        result = tla_backend.check_tla(module, "INIT Init\nNEXT Next")
    assert result["status"] == "VERIFIED"
    assert "-deadlock" not in run.call_args.args[0]
