"""Residual single-branch coverage backfill across pipeline modules.

Each test pins one previously uncovered fail-closed or cleanup branch without
touching production code.  Mocking seams mirror the sibling test modules
(structured_for chats, patched subprocess/os helpers, tmp_path fixtures).
"""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import pipeline.canonical_contracts as canonical_contracts
from formalspec_core.postprocess import (
    inject_bidirectional_old,
    inject_pure,
    inject_sum_helper,
    strip_exit_invariants,
)
from pipeline.canonical_contracts import (
    CanonicalContractConflict,
    canonical_traffic_light_contract,
)
from pipeline.concurrent_composition import render_actor_model
from pipeline.c_support import apply_c_passes
from pipeline.domain_generator import _canonical_integer_guard_tree, compile_domain_spec_v2
from pipeline.domain_v2_promotion import verify_artifact_signature
from pipeline.domain_v2_publication import write_json_atomic
from pipeline.extract_tla_ir import UnsupportedJmlSemantics
from pipeline.generic_refinement_gate import _extract, generic_v2_refinement_gate
from pipeline.jml_ast import (
    BinaryExpr,
    FieldAccess,
    JmlExpressionSyntaxError,
    parse_jml_expression,
)
from pipeline.jml_to_dafny import (
    UnsupportedBoundary,
    _render_pure_expression,
    translate_jml_to_dafny,
)
from pipeline.llm import LLMError, _first_json_object
from pipeline.lock_correspondence import check_lock_correspondence
from pipeline.profile import _gate_fail_reasons
from pipeline.refactor_gate import verify_multifile_contract_refactor
from pipeline.verify_cpp import verify_cpp
from pipeline.domains.elevator_controller_extract import _guard
from pipeline.domains.robot_vacuum_controller_render import (
    render_robot_vacuum_controller,
)


# --------------------------------------------------------------------------
# pipeline/generic_refinement_gate.py
# --------------------------------------------------------------------------

def test_refinement_extraction_skips_pure_query_methods():
    code = (
        "    //@ requires count >= 0;\n"
        "    public /*@ pure @*/ int peek() { return count; }\n"
        "    //@ requires count < 3;\n"
        "    //@ assignable count;\n"
        "    //@ ensures count == \\old(count) + 1;\n"
        "    public void increment() { count = count + 1; }\n")
    transitions = _extract(code, {"count"})
    assert [item.name for item in transitions] == ["increment"]


def test_refinement_gate_wraps_unexpected_candidate_errors():
    with patch("pipeline.generic_refinement_gate.load_bound_reviewed_domain",
               side_effect=ValueError("candidate json is malformed")):
        verdict = generic_v2_refinement_gate(
            "reviewed.json", "validation.json", "public class A {}",
            "public class A {}", esc_verified=True)
    assert verdict["status"] == "FAIL"
    assert verdict["code"] == "unsupported_refinement_boundary"
    assert "malformed" in verdict["message"]
    assert verdict["source_refinement_proved"] is False


# --------------------------------------------------------------------------
# pipeline/domain_generator.py
# --------------------------------------------------------------------------

def _switch_header():
    return {
        "schema_version": 2, "review_status": "unreviewed",
        "domain_name": "Switch", "module_name": "switch", "actors": 1,
        "state_variables": [{"kind": "bool", "name": "enabled", "initial": False}],
        "invariant_plans": [{"id": "EnabledIsBoolean",
                             "clause_names": ["EnabledClause"]}],
        "operation_plans": [{"name": "enable", "frame": ["enabled"],
                             "guard_expressions": ["enabled == false"],
                             "effect_values": {"enabled": "true"}}],
    }


_CLAUSE = {"id": "EnabledClause", "expression": "enabled == true"}
_OPERATION = {"name": "enable", "return_type": "void",
              "failure_semantics": "unavailable",
              "guards": [{"id": "g", "expression": "enabled == false"}],
              "effects": [{"id": "e", "target": "enabled", "value": "true"}],
              "frame": ["enabled"], "exception_type": None,
              "exception_trigger": None}


def _structured(responses):
    def structured_for(_schema, name):
        def chat(_messages, _model, _temperature):
            payload = responses[name]
            if isinstance(payload, list):
                return json.dumps(payload.pop(0)), "test-model", {}
            return json.dumps(payload), "test-model", {}
        chat.structured_for = structured_for
        return chat
    return structured_for({}, "root")


def test_staged_operation_guard_mismatch_triggers_local_repair():
    wrong = dict(_OPERATION, guards=[{"id": "g", "expression": "enabled == true"}])
    progress = []
    root = _structured({"v2_domain_header": _switch_header(),
                        "v2_domain_invariant_clause": _CLAUSE,
                        "v2_domain_operation": [wrong, dict(_OPERATION)]})
    spec, *_ = compile_domain_spec_v2("A switch", [], [], root,
                                      progress=progress.append)
    guard = spec.operations[0].guards[0].expression
    assert guard.kind == "eq"
    assert guard.right.value is False
    assert any("Repairing operation enable" in item for item in progress)


def test_canonical_guard_tree_treats_gt_as_inclusive_gte():
    tree = {"kind": "gt", "left": {"kind": "field", "name": "count"},
            "right": {"kind": "integer", "value": 4}}
    normalized = json.loads(_canonical_integer_guard_tree(tree))
    assert normalized["kind"] == "gte"
    assert normalized["right"]["value"] == 5


# --------------------------------------------------------------------------
# pipeline/c_support.py
# --------------------------------------------------------------------------

def test_valid_pointer_pass_skips_indexes_that_are_not_parameters():
    code = ("/*@ requires \\valid(p);\n"
            "   assigns *p;\n"
            "*/\n"
            "void f(int *p) {\n"
            "    int i = 0;\n"
            "    p[i] = 1;\n"
            "}\n")
    result = apply_c_passes(code, selected=["inject_valid_pointers"])
    assert "0 >= 0" not in result["code"]
    assert result["passes"][0]["name"] == "inject_valid_pointers"


def test_separated_pass_skips_fewer_than_two_pointers_and_unannotated_pairs():
    single = ("/*@ assigns *p; */\n"
              "void g(int *p) { *p = 1; }\n")
    annotated = apply_c_passes(single, selected=["inject_separated"])
    assert "\\separated(" not in annotated["code"]

    unannotated = "void h(int *a, int *b) { *a = *b; }\n"
    plain = apply_c_passes(unannotated, selected=["inject_separated"])
    assert "\\separated(" not in plain["code"]


# --------------------------------------------------------------------------
# pipeline/verify_cpp.py
# --------------------------------------------------------------------------

def test_cpp_verifier_reports_os_error_when_harness_write_fails(tmp_path):
    source = tmp_path / "Counter.cpp"
    source.write_text("class Counter { public: void tick() {} };",
                      encoding="utf-8")
    with patch.object(Path, "write_text", side_effect=OSError("disk full")):
        verdict = verify_cpp(source)
    assert verdict["status"] == "VERIFY_FAILED"
    assert verdict["claim"] == "NO_PROOF"
    assert "disk full" in verdict["message"]


# --------------------------------------------------------------------------
# pipeline/jml_to_dafny.py
# --------------------------------------------------------------------------

_LINKED = r"""
public class Node {
  public int value;
  public Node next;

  //@ requires start != null;
  //@ requires target != null;
  //@ requires acyclic(start);
  //@ assignable \nothing;
  public static /*@ pure @*/ boolean reachable(Node start, Node target) {
    return start == target || (start.next != null && reachable(start.next, target));
  }
}
"""


def test_linked_reachability_requires_single_return_helper():
    malformed = _LINKED.replace(
        "return start == target || "
        "(start.next != null && reachable(start.next, target));",
        "if (start == target) { return true; } return false;")
    with pytest.raises(UnsupportedBoundary, match="one recursive return"):
        translate_jml_to_dafny(malformed)


def test_pure_expression_renderer_rejects_unsupported_tokens():
    with pytest.raises(UnsupportedBoundary, match="unsupported expression token"):
        _render_pure_expression("value $ 2")


# --------------------------------------------------------------------------
# pipeline/domains/robot_vacuum_controller_render.py
# --------------------------------------------------------------------------

def test_robot_vacuum_renderer_fails_closed_before_review():
    with pytest.raises(UnsupportedJmlSemantics, match="not reviewed"):
        render_robot_vacuum_controller(object())


# --------------------------------------------------------------------------
# pipeline/refactor_gate.py
# --------------------------------------------------------------------------

def test_multifile_gate_rejects_symlink_in_refactored_file_set(tmp_path):
    baseline = tmp_path / "baseline" / "Service.java"
    baseline.parent.mkdir(parents=True)
    baseline.write_text(
        "public class Service { public int run(int v) { return v; } }",
        encoding="utf-8")
    refactored = tmp_path / "refactored"
    refactored.mkdir()
    (refactored / "Service.java").write_text(
        "public class Service { public int run(int v) { return v + 1; } }",
        encoding="utf-8")
    helper = tmp_path / "Helper.java"
    helper.write_text("public class Helper {}", encoding="utf-8")
    (refactored / "Helper.java").symlink_to(helper)
    result = verify_multifile_contract_refactor(baseline, refactored)
    assert result["status"] == "FAIL"
    assert result["code"] == "unsafe_refactored_file_set"


# --------------------------------------------------------------------------
# pipeline/profile.py
# --------------------------------------------------------------------------

def test_gate_fail_reasons_includes_evidence_message():
    reasons = _gate_fail_reasons(
        {"rac_junit": "FAIL"},
        {"rac_junit": {"message": "JUnit compilation failed"}})
    assert "JUnit compilation failed" in reasons["rac_junit"]
    assert reasons["rac_junit"].startswith("rac_junit gate FAIL")


# --------------------------------------------------------------------------
# pipeline/lock_correspondence.py
# --------------------------------------------------------------------------

def test_lock_correspondence_requires_protocol_model():
    result = check_lock_correspondence(
        {"Door.java": "public synchronized void open() {}"},
        "MODULE Door\n====")
    assert result["status"] == "LOCK_PROTOCOL_MODEL_MISSING"
    assert result["claim"] == "NO_PROOF"


# --------------------------------------------------------------------------
# pipeline/llm.py
# --------------------------------------------------------------------------

def test_first_json_object_returns_empty_on_unbalanced_text():
    assert _first_json_object('{"enabled": true') == {}


# --------------------------------------------------------------------------
# pipeline/jml_ast.py
# --------------------------------------------------------------------------

def test_jml_expression_parser_rejects_unexpected_operator_prefix():
    with pytest.raises(JmlExpressionSyntaxError, match="unexpected token"):
        parse_jml_expression("* 1")


# --------------------------------------------------------------------------
# pipeline/domains/elevator_controller_extract.py
# --------------------------------------------------------------------------

def test_elevator_guard_adapter_rejects_non_literal_comparand():
    expression = BinaryExpr(kind="eq", left=FieldAccess(field="door_state"),
                            right=FieldAccess(field="moving_state"))
    assert _guard(expression) is None


# --------------------------------------------------------------------------
# pipeline/domain_v2_publication.py
# --------------------------------------------------------------------------

def test_write_json_atomic_tolerates_missing_temporary_on_failure(tmp_path):
    with patch("os.replace", side_effect=OSError("replace failed")), \
         patch("os.unlink", side_effect=FileNotFoundError("already gone")):
        with pytest.raises(OSError, match="replace failed"):
            write_json_atomic(tmp_path / "artifact.json", {"schema_version": 2})


# --------------------------------------------------------------------------
# pipeline/domain_v2_promotion.py
# --------------------------------------------------------------------------

def test_signature_verification_reports_invalid_gpg_verdict(tmp_path):
    artifact = tmp_path / "evidence.json"
    artifact.write_text("{}", encoding="utf-8")
    signature = tmp_path / "evidence.sig"
    signature.write_text("sig", encoding="utf-8")
    failed = SimpleNamespace(returncode=1, stdout="", stderr="gpg: verify failed")
    with patch("pipeline.domain_v2_promotion.subprocess.run",
               return_value=failed):
        result = verify_artifact_signature(artifact, signature)
    assert result["status"] == "SIGNATURE_INVALID"
    assert result["claim"] == "NO_PROOF"
    assert "gpg: verify failed" in result["output"]


# --------------------------------------------------------------------------
# pipeline/concurrent_composition.py
# --------------------------------------------------------------------------

def test_actor_model_rejects_non_identifier_operation_name():
    assert render_actor_model(["alpha"],
                              "not an op")["status"] == "CONCURRENT_MODEL_INVALID"


# --------------------------------------------------------------------------
# pipeline/canonical_contracts.py
# --------------------------------------------------------------------------

def test_traffic_light_contract_requires_complete_action_table():
    with patch.object(canonical_contracts, "ACTION_REFINEMENTS", {}):
        with pytest.raises(CanonicalContractConflict,
                           match="action table is incomplete"):
            canonical_traffic_light_contract("a traffic light controller")


# --------------------------------------------------------------------------
# formalspec_core/postprocess.py
# --------------------------------------------------------------------------

def test_strip_exit_invariants_skips_malformed_invariant_clause():
    code = ("public class C {\n"
            "    public int f(int n) {\n"
            "        int i = 0;\n"
            "        //@ loop_invariant;\n"
            "        while (i < n) { i = i + 1; }\n"
            "        return i;\n"
            "    }\n"
            "}\n")
    assert strip_exit_invariants(code) == code


def test_sum_helper_appends_helper_without_strippable_accumulator():
    code = ("public class Sum {\n"
            "    //@ requires (\\sum int k; 0 <= k && k < n; a[k]) <= 100;\n"
            "    //@ requires a.length <= 10;\n"
            "    public static int total(int[] a, int n) { return a[0]; }\n"
            "}\n")
    result = inject_sum_helper(code)
    assert "public static int sumOf(int[] a, int n)" in result
    assert "requires a.length <= 10;" in result


def test_bidirectional_old_skips_frame_when_counter_is_not_extractable():
    code = ("public class R {\n"
            "    //@ loop_invariant (\\forall int k; 0 <= k && n > k; "
            "a[k] == \\old(a)[a.length - 1 - k]);\n"
            "}\n")
    result = inject_bidirectional_old(code)
    mirror = ("(\\forall int k; 0 <= k && n > k; "
              "a[a.length - 1 - k] == \\old(a)[k])")
    assert mirror in result
    # no counter bound was extractable, so no middle-frame invariant appears
    assert "k < a.length - " not in result


def test_bidirectional_old_leaves_complete_swap_invariants_untouched():
    original = ("    //@ loop_invariant (\\forall int k; 0 <= k && k < i; "
                "a[k] == \\old(a)[a.length - 1 - k]);")
    mirror = ("    //@ loop_invariant (\\forall int k; 0 <= k && k < i; "
              "a[a.length - 1 - k] == \\old(a)[k]);")
    frame = ("    //@ loop_invariant (\\forall int k; i <= k && "
             "k < a.length - i; a[k] == \\old(a)[k]);")
    code = "public class S {\n" + original + "\n" + mirror + "\n" + frame + "\n}\n"
    assert inject_bidirectional_old(code) == code


def test_inject_pure_skips_java_keywords_in_spec_contexts():
    code = ("public class P {\n"
            "    //@ ensures f(v) > 0 && while (v);\n"
            "    private static int f(int v) { return v; }\n"
            "}\n")
    result = inject_pure(code)
    assert "/*@ pure @*/" in result
    assert result.count("/*@ pure @*/") == 1
