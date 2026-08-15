"""Backfill tests for uncovered fail-closed branches across WIP pipeline modules.

One test module covering the currently-uncovered lines reported by coverage.xml:
deterministic_refactor (decorator/facade/factory/state/null-object fail paths),
behavior_correction, security_assessment, code_documentation, remediation,
security_poc, algorithm_discovery, algorithm_optimization,
architecture_tla_renderer, and composition_render. No production code changed.
"""
import hashlib
import json
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import javalang

from pipeline.algorithm_discovery import _candidate
from pipeline.algorithm_optimization import optimize_algorithm
from pipeline.architecture_tla_renderer import render_unified_architecture
from pipeline.behavior_correction import correct_behavior
from pipeline.code_documentation import (
    document_code,
    generate_narrative,
    render_infix,
    render_nl_document,
    render_predicate,
)
from pipeline.composition_render import verify_composition
from pipeline.deterministic_refactor import (
    _facade_source,
    _state_files,
    extract_decorator_from_inspection,
    extract_facade_from_inspection,
    extract_factory_from_inspection,
    extract_null_object_from_inspection,
    extract_state_from_inspection,
)
from pipeline.remediation import remediate
from pipeline.security_assessment import (
    assess_security,
    map_formal_failure_to_cwe,
    map_formal_vcs,
    run_semgrep,
)
from pipeline.security_poc import inspect_security
from pipeline.staged_architecture import UnifiedArchitecture


# --------------------------------------------------------------------------
# deterministic_refactor: hash-bound fixtures shared by every profile
# --------------------------------------------------------------------------


def _bound_evidence(tmp_path, name, source, findings):
    """Write one Java source plus a correctly hash-bound inspection payload."""
    source_path = tmp_path / f"{name}.java"
    source_path.write_text(source, encoding="utf-8")
    evidence_path = tmp_path / f"{name}.json"
    evidence_path.write_text(json.dumps({
        "status": "INSPECTED", "claim": "STATIC_INSPECTION",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "findings": findings}), encoding="utf-8")
    return source_path, evidence_path


DECORATOR_FINDING = {"code": "cross-cutting-delegation", "interfaces": ["Notifier"],
                     "wrapped_fields": ["wrapped"], "methods": ["send"]}


def test_decorator_profile_fails_closed_on_every_guard(tmp_path):
    # 69-70: source (or evidence) unreadable.
    missing = extract_decorator_from_inspection(tmp_path / "missing.java",
                                                tmp_path / "missing.json")
    assert missing["code"] == "input_unavailable" and missing["claim"] == "NO_PROOF"

    # 77: hash-bound finding missing -> inspection_binding_mismatch.
    source, evidence = _bound_evidence(
        tmp_path, "Empty", "public class Empty {}\n", [])
    assert extract_decorator_from_inspection(source, evidence)["code"] == \
        "inspection_binding_mismatch"

    # 86: binding passes but the source does not parse.
    source, evidence = _bound_evidence(tmp_path, "Bad", "public class Bad {",
                                       [DECORATOR_FINDING])
    assert extract_decorator_from_inspection(source, evidence)["code"] == \
        "unsupported_java_syntax"

    # 83: finding references a method the class does not declare.
    source, evidence = _bound_evidence(tmp_path, "One", """public class One {
    private Notifier wrapped;
    public void send() { wrapped.notify(); }
}
""", [{**DECORATOR_FINDING, "methods": ["send", "ghost"]}])
    assert extract_decorator_from_inspection(source, evidence)["code"] == \
        "unsupported_decorator_shape"

    # 153: decorated method reads additional instance state.
    source, evidence = _bound_evidence(tmp_path, "Two", """public class Two {
    private Notifier wrapped;
    private int extra;
    public void send() { int local = extra; wrapped.notify(); }
}
""", [DECORATOR_FINDING])
    assert extract_decorator_from_inspection(source, evidence)["code"] == \
        "unsupported_decorator_shape"

    # 162: abstract method body cannot be reconstructed (no following brace).
    source, evidence = _bound_evidence(tmp_path, "Three", """public abstract class Three {
    private Notifier wrapped;
    public void send();
}
""", [DECORATOR_FINDING])
    result = extract_decorator_from_inspection(source, evidence)
    assert result["code"] == "unsupported_decorator_shape"
    assert "span" in result["message"]


def test_facade_profile_fails_closed_on_input_syntax_and_shape(tmp_path):
    # 100-101: input unavailable.
    missing = extract_facade_from_inspection(tmp_path / "missing.java",
                                             tmp_path / "missing.json")
    assert missing["code"] == "input_unavailable"

    # 113 + 117-118: God-class finding bound, but no public instance methods.
    source, evidence = _bound_evidence(
        tmp_path, "Hidden", "public class Hidden { private void run() {} }\n",
        [{"code": "god-class"}])
    result = extract_facade_from_inspection(source, evidence)
    assert result["code"] == "unsupported_facade_shape"
    assert "public instance methods" in result["message"]

    # 115-116: hash-bound god-class finding over unparseable Java.
    source, evidence = _bound_evidence(tmp_path, "Broken", "public class Broken {",
                                       [{"code": "god-class"}])
    assert extract_facade_from_inspection(source, evidence)["code"] == \
        "unsupported_java_syntax"

    # 136: parameter type without a resolvable name.
    fake = SimpleNamespace(name="run", return_type=None, parameters=[
        SimpleNamespace(name="payload", type=SimpleNamespace())])
    try:
        _facade_source("Hidden", [fake])
    except ValueError as exc:
        assert "parameter type is unsupported" in str(exc)
    else:
        raise AssertionError("opaque facade parameter was accepted")


def test_factory_profile_requires_a_reference_return_type(tmp_path):
    # 220: void factory-shaped method has no reference return type.
    source, evidence = _bound_evidence(tmp_path, "VoidFactory", """public class VoidFactory {
    public void make(int kind) {
        if (kind == 1) return new Alpha();
        else return new Beta();
    }
}
""", [{"code": "conditional-object-creation", "method": "make"}])
    result = extract_factory_from_inspection(source, evidence, "make")
    assert result["code"] == "unsupported_factory_shape"
    assert "reference return type" in result["message"]


def test_state_profile_fails_closed_on_input_binding_syntax_and_shape(tmp_path):
    # 267-268: input unavailable.
    missing = extract_state_from_inspection(tmp_path / "missing.java",
                                            tmp_path / "missing.json", "handle")
    assert missing["code"] == "input_unavailable"

    # 275: stale hash breaks the binding.
    source, evidence = _bound_evidence(tmp_path, "Stale", "public class Stale {}\n",
                                       [{"code": "repeated-state-dispatch",
                                         "methods": ["handle"], "field": "mode"}])
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps({**json.loads(evidence.read_text()),
                                 "source_sha256": "0" * 64}), encoding="utf-8")
    assert extract_state_from_inspection(source, stale, "handle")["code"] == \
        "inspection_binding_mismatch"

    # 282: bound finding over unparseable Java.
    source, evidence = _bound_evidence(tmp_path, "BrokenState", "public class BrokenState {",
                                       [{"code": "repeated-state-dispatch",
                                         "methods": ["handle"], "field": "mode"}])
    assert extract_state_from_inspection(source, evidence, "handle")["code"] == \
        "unsupported_java_syntax"

    # 367: abstract method is not concrete.
    source, evidence = _bound_evidence(tmp_path, "AbstractState", """public abstract class AbstractState {
    private int mode;
    public abstract void handle();
}
""", [{"code": "repeated-state-dispatch", "methods": ["handle"], "field": "mode"}])
    result = extract_state_from_inspection(source, evidence, "handle")
    assert result["code"] == "unsupported_state_shape"
    assert "concrete" in result["message"]

    # 381: return type carries no resolvable name.
    branches = """public class Label {
    private int mode;
    public String label() {
        if (this.mode == 0) { return "a"; }
        if (this.mode == 1) { return "b"; }
        return "c";
    }
}
"""
    tree = javalang.parse.parse(branches)
    method = next(node for _, node in tree.filter(javalang.tree.MethodDeclaration)
                  if node.name == "label")
    fake = SimpleNamespace(position=method.position, body=method.body,
                           return_type=object())
    try:
        _state_files(branches, fake, "mode")
    except ValueError as exc:
        assert "return type is unsupported" in str(exc)
    else:
        raise AssertionError("opaque state return type was accepted")


def test_null_object_profile_fails_closed_on_field_and_calls(tmp_path):
    null_finding = [{"code": "repeated-null-check"}]

    # 298-299: input unavailable.
    missing = extract_null_object_from_inspection(tmp_path / "missing.java",
                                                  tmp_path / "missing.json")
    assert missing["code"] == "input_unavailable"

    # 304: hash not bound to the source.
    source, evidence = _bound_evidence(
        tmp_path, "StaleNull", "public class StaleNull {}\n", null_finding)
    stale = tmp_path / "stale_null.json"
    stale.write_text(json.dumps({**json.loads(evidence.read_text()),
                                 "source_sha256": "0" * 64}), encoding="utf-8")
    assert extract_null_object_from_inspection(source, stale)["code"] == \
        "inspection_binding_mismatch"

    # 308: no typed nullable collaborator field declared.
    source, evidence = _bound_evidence(tmp_path, "NoField",
                                       "public class NoField { public void run() {} }\n",
                                       null_finding)
    result = extract_null_object_from_inspection(source, evidence)
    assert result["code"] == "unsupported_null_object_shape"
    assert "collaborator field" in result["message"]

    # 312: collaborator field exists but is never called.
    source, evidence = _bound_evidence(tmp_path, "NoCalls", """public class NoCalls {
    private Logger logger;
    public void run() {}
}
""", null_finding)
    result = extract_null_object_from_inspection(source, evidence)
    assert result["code"] == "unsupported_null_object_shape"
    assert "No collaborator method calls" in result["message"]


# --------------------------------------------------------------------------
# behavior_correction
# --------------------------------------------------------------------------

BC_SOURCE = """public class UnsafeService {
    //@ requires arr != null;
    public int getElement(int[] arr, int index) { return arr[index]; }
}
"""
BC_STRENGTHENED = """public class UnsafeService {
    //@ requires arr != null;
    //@ ensures (0 <= index && index < arr.length) ==> \\result == arr[index];
    public int getElement(int[] arr, int index) { return arr[index]; }
}
"""


def _bc_source(tmp_path):
    source = tmp_path / "UnsafeService.java"
    source.write_text(BC_SOURCE, encoding="utf-8")
    return source


def test_correct_behavior_missing_input_fails_closed(tmp_path):
    # 31.
    result = correct_behavior(tmp_path / "missing.java", "CWE-125", tmp_path / "out")
    assert result["code"] == "input_unavailable" and result["claim"] == "NO_PROOF"


def test_correct_behavior_reports_strengthening_transport_failure(tmp_path):
    # 42-43.
    source = _bc_source(tmp_path)
    with patch("pipeline.behavior_correction._chat_fn",
               side_effect=RuntimeError("offline")):
        result = correct_behavior(source, "CWE-125", tmp_path / "out")
    assert result["code"] == "spec_strengthening_failed"
    assert result["status"] == "CORRECTION_FAILED"


def test_correct_behavior_accepts_verified_strengthened_contract_directly(tmp_path):
    # 61: the strengthened file already passes ESC on the first check.
    source = _bc_source(tmp_path)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify",
               side_effect=[(0, ""), (0, "")]):
        chat.return_value.return_value = (BC_STRENGTHENED, "test", {})
        result = correct_behavior(source, "CWE-125", tmp_path / "out")
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["attempts"] == 1


def test_correct_behavior_reports_repair_transport_failure(tmp_path):
    # 70-72: repair call raises, loop breaks with patch_generation_failed.
    source = _bc_source(tmp_path)
    transport = Mock(side_effect=[(BC_STRENGTHENED, "test", {}),
                                  RuntimeError("offline")])
    with patch("pipeline.behavior_correction._chat_fn", return_value=transport), \
         patch("pipeline.behavior_correction.verify", return_value=(1, "Postcondition")):
        result = correct_behavior(source, "CWE-125", tmp_path / "out", max_attempts=3)
    # The loop breaks on the repair failure; the terminal update owns the code,
    # so the transport error survives only as the message.
    assert result["status"] == "CORRECTION_FAILED"
    assert result["message"] == "offline"
    assert result["attempts"] == 1


def test_correct_behavior_cwe_specific_and_default_guidance(tmp_path):
    # 21-22 (CWE-476) and 23 (default).
    for cwe, expected in [
            ("CWE-476", "explicit null handling"),
            ("CWE-190", "Define explicit safe behavior")]:
        source = _bc_source(tmp_path)
        captured = {}

        def chat(messages, model, temperature):
            captured.setdefault("prompt", messages[-1]["content"])
            return (BC_SOURCE, "test", {})

        with patch("pipeline.behavior_correction._chat_fn", return_value=chat), \
             patch("pipeline.behavior_correction.verify", return_value=(1, "vc")):
            result = correct_behavior(source, cwe, tmp_path / "out", max_attempts=1)
        assert result["status"] == "CORRECTION_FAILED"
        assert expected in captured["prompt"]


# --------------------------------------------------------------------------
# security_assessment
# --------------------------------------------------------------------------


def test_failure_mapping_covers_all_verifier_branches():
    # 30: openjml descriptive index diagnostics.
    assert map_formal_failure_to_cwe(
        "openjml", "SomeClass.java:7: PossiblyNegativeIndex") == \
        {"cwe": "CWE-125", "severity": "HIGH"}
    # 38: framac null-pointer labels.
    assert map_formal_failure_to_cwe("framac", "null_pointer dereference") == \
        {"cwe": "CWE-476", "severity": "HIGH"}
    # 47-48: esbmc overflow (not bounds).
    assert map_formal_failure_to_cwe("esbmc", "arithmetic overflow") == \
        {"cwe": "CWE-190", "severity": "HIGH"}


def test_map_formal_vcs_appends_descriptive_loop_and_null_findings():
    # 64: "decreases" without the LoopTermination label.
    loop = map_formal_vcs("SomeClass.java:9: warning: the loop decreases")
    assert loop and loop[0]["cwe"] == "CWE-835"
    # 72: descriptive null dereference without the PossiblyNull label.
    null = map_formal_vcs("SomeClass.java:4: caution: null dereference")
    assert null and null[0]["cwe"] == "CWE-476"


def test_semgrep_falls_back_to_public_registry_config(tmp_path):
    # 83: configured config missing -> "p/java".
    source = tmp_path / "X.java"; source.write_text("class X {}", encoding="utf-8")
    process = type("P", (), {"stdout": "{}", "stderr": "", "returncode": 0})()
    with patch("pipeline.security_assessment.subprocess.run", return_value=process) as run:
        result = run_semgrep(source, config=tmp_path / "nope.yml")
    assert result["status"] == "CLEAN"
    assert run.call_args.args[0][1:3] == ["--config", "p/java"]


def test_assess_security_missing_file_fails_closed(tmp_path):
    # 120.
    result = assess_security(tmp_path / "missing.java")
    assert result["code"] == "input_unavailable" and result["claim"] == "NO_PROOF"


# --------------------------------------------------------------------------
# code_documentation
# --------------------------------------------------------------------------


def test_document_renderers_cover_not_implies_and_bare_terms():
    # 67: predicate-level not.
    assert render_predicate({"kind": "not",
                             "expression": {"kind": "field", "name": "armed"}}) == \
        "not (armed)"
    # 77: infix implication connective.
    assert render_infix({"kind": "implies",
                         "left": {"kind": "field", "name": "armed"},
                         "right": {"kind": "boolean", "value": False}}) == \
        "armed implies false"
    # 53: bare-term fallback renders a term-level not.
    assert render_infix({"kind": "not",
                         "expression": {"kind": "field", "name": "locked"}}) == \
        "not (locked)"


def test_operation_sentences_cover_guardless_and_effectless_operations():
    # 90 (sets-fallback), 101 ("at any time"), 105 ("leaves ... unchanged").
    payload = {
        "domain_name": "Plain", "module_name": "plain",
        "state_variables": [],
        "operations": [
            {"name": "noop", "guards": [], "effects": []},
            {"name": "seal", "guards": [], "effects": [
                {"target": "door", "value": {"kind": "integer", "value": 1}}]},
        ],
        "tlc_invariants": [],
    }
    document = render_nl_document(payload, source_path=Path("Plain.java"),
                                  source_sha256="0" * 64, language="java",
                                  extractor="tree-sitter")
    assert "The 'noop' operation can be called at any time." in document
    assert "When called, it leaves the documented state unchanged." in document
    assert "sets door to 1" in document


def test_generate_narrative_coerces_non_dict_invariant_prose():
    # 181.
    with patch("pipeline.code_documentation._chat_fn",
               return_value=lambda *_args: (
                   '{"overview": "An overview.", "invariant_prose": "not-a-dict"}',
                   "fixture", {})):
        result = generate_narrative({"module_name": "x"}, "ollama", None)
    assert result["overview"] == "An overview."
    assert result["invariant_prose"] == {}


def test_document_code_reports_unreadable_source(tmp_path):
    # 230-231: read_text raises UnicodeError -> input_unavailable.
    source = tmp_path / "Broken.java"
    source.write_text("public class Broken {}", encoding="utf-8")
    with patch("pathlib.Path.read_text",
               side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")):
        result = document_code(source, tmp_path / "docs" / "Broken.md",
                               project_root=tmp_path, no_llm=True)
    assert result["code"] == "input_unavailable"
    assert result["claim"] == "NO_PROOF"


# --------------------------------------------------------------------------
# remediation
# --------------------------------------------------------------------------


def test_remediation_prompt_carries_web_crypto_and_permission_guidance(tmp_path):
    # 41, 43, 45.
    target = tmp_path / "Service.java"; target.write_text("class Service {}",
                                                          encoding="utf-8")
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [
        {"cwe": "CWE-79"}, {"cwe": "CWE-326"}, {"cwe": "CWE-732"}]}),
        encoding="utf-8")
    captured = {}

    def chat(messages, model, temperature):
        captured["prompt"] = messages[-1]["content"]
        return "class Service {}", "model", {}

    with patch("pipeline.remediation._chat_fn", return_value=chat), \
         patch("pipeline.remediation.verify", return_value=(1, "not verified")):
        result = remediate(target, report, tmp_path / "out")
    assert result["status"] == "REMEDIATION_FAILED"
    for fragment in ("HTML-escape", "RSA key sizes", "least-privilege"):
        assert fragment in captured["prompt"]


# --------------------------------------------------------------------------
# security_poc
# --------------------------------------------------------------------------


def test_inspect_security_reports_missing_input(tmp_path):
    # 30.
    result = inspect_security(tmp_path / "missing-directory")
    assert result["code"] == "input_unavailable" and result["claim"] == "NO_PROOF"
    assert result["findings"] == []


def test_inspect_security_types_semgrep_findings_as_sast_patterns(tmp_path):
    # 37.
    source = tmp_path / "Service.java"; source.write_text("class Service {}",
                                                          encoding="utf-8")
    with patch("pipeline.security_poc.run_semgrep", return_value={
            "status": "FINDINGS",
            "findings": [{"cwe": "CWE-78", "severity": "ERROR",
                          "rule_id": "CWE-78-COMMAND-INJECTION"}]}), \
         patch("pipeline.security_poc.verify", return_value=(0, "")):
        result = inspect_security(source)
    assert result["status"] == "VULNERABILITIES_FOUND"
    finding = result["findings"][0]
    assert finding["type"] == "SAST_PATTERN" and finding["file"].endswith("Service.java")


# --------------------------------------------------------------------------
# algorithm_discovery / algorithm_optimization
# --------------------------------------------------------------------------


def test_discovery_candidate_runs_gate_on_verified_candidate(tmp_path):
    source = tmp_path / "Spec.java"; source.write_text("public class Spec {}",
                                                       encoding="utf-8")
    destination = tmp_path / "out.java"
    with ExitStack() as stack:
        stack.enter_context(patch(
            "pipeline.algorithm_discovery._chat_fn",
            return_value=lambda *_args: (source.read_text(encoding="utf-8"),
                                         "m", {})))
        stack.enter_context(patch("pipeline.algorithm_discovery.verify",
                                  return_value=(0, "")))
        gate = stack.enter_context(patch(
            "pipeline.algorithm_discovery.verify_contract_preserving_refactor",
            return_value={"status": "FAIL"}))
        failed = _candidate(source, destination, "hashmap", "ollama", None)
    assert failed["code"] == "refactor_gate_failed"
    assert failed["status"] == "FAIL"
    gate.assert_called_once_with(source, destination)

    with ExitStack() as stack:
        stack.enter_context(patch(
            "pipeline.algorithm_discovery._chat_fn",
            return_value=lambda *_args: (source.read_text(encoding="utf-8"),
                                         "m", {})))
        stack.enter_context(patch("pipeline.algorithm_discovery.verify",
                                  return_value=(0, "")))
        stack.enter_context(patch(
            "pipeline.algorithm_discovery.verify_contract_preserving_refactor",
            return_value={"status": "VERIFIED"}))
        verified = _candidate(source, destination, "hashmap", "ollama", None)
    assert verified["status"] == "VERIFIED"
    assert verified["claim"] == "DEDUCTIVE_PROOF"
    assert destination.exists()


OPT_SOURCE = "public class TwoSum { public int solve(int[] nums) { return nums.length; } }\n"


def test_optimization_rejects_unverified_baseline(tmp_path):
    # 31.
    source = tmp_path / "TwoSum.java"; source.write_text(OPT_SOURCE, encoding="utf-8")
    with patch("pipeline.algorithm_optimization.verify", return_value=(1, "boom")):
        result = optimize_algorithm(source, tmp_path / "out.java", strategy="hashmap")
    assert result["code"] == "baseline_not_verified"
    assert result["claim"] == "NO_PROOF"


def test_optimization_rejects_unverified_candidate_and_gate(tmp_path):
    source = tmp_path / "TwoSum.java"; source.write_text(OPT_SOURCE, encoding="utf-8")
    destination = tmp_path / "out" / "TwoSum.java"
    with patch("pipeline.algorithm_optimization.verify",
               side_effect=[(0, "baseline"), (1, "candidate vc")]), \
         patch("pipeline.algorithm_optimization._chat_fn",
               return_value=lambda *_args: (OPT_SOURCE, "model", {})):
        result = optimize_algorithm(source, destination, strategy="hashmap")
    assert result["code"] == "optimized_candidate_not_verified"
    assert result["message"] == "candidate vc"

    with patch("pipeline.algorithm_optimization.verify",
               side_effect=[(0, "baseline"), (0, "candidate")]), \
         patch("pipeline.algorithm_optimization._chat_fn",
               return_value=lambda *_args: (OPT_SOURCE, "model", {})), \
         patch("pipeline.algorithm_optimization.verify_contract_preserving_refactor",
               return_value={"status": "FAIL", "claim": "NO_PROOF"}):
        result = optimize_algorithm(source, destination, strategy="hashmap")
    assert result["code"] == "refactor_gate_failed"
    assert result["behavior_equivalence_proved"] is False


# --------------------------------------------------------------------------
# architecture_tla_renderer
# --------------------------------------------------------------------------

UNIFIED_VALUE = {
    "name": "CounterSystem",
    "components": [{
        "name": "counter",
        "type": "core",
        "state_variables": [
            {"name": "count", "type": "int", "bound": [0, 2], "initial": 0}],
        "operations": [{
            "name": "increment",
            "contract": {"requires": "count < 2",
                         "ensures": "count == old count + 1"}}],
        "transitions": [{
            "operation_name": "increment",
            "precondition": {"kind": "lt",
                             "left": {"kind": "field", "name": "count"},
                             "right": {"kind": "integer", "value": 2}},
            "effects": [{"target": "count",
                         "value": {"kind": "add",
                                   "left": {"kind": "field", "name": "count"},
                                   "right": {"kind": "integer", "value": 1}}}],
            "frame": ["count"]}],
    }],
    "use_cases": [{"name": "bump",
                   "steps": [{"component": "counter", "operation": "increment"}]}],
}


def test_render_unified_architecture_lowers_components_and_transitions():
    # 56, 58, 61.
    architecture = UnifiedArchitecture.model_validate(UNIFIED_VALUE)
    tla, cfg = render_unified_architecture(architecture)
    assert "MODULE CounterSystem" in tla
    assert "count \\in 0..2" in tla
    assert "Next == increment" in tla
    assert "SPECIFICATION Spec" in cfg


# --------------------------------------------------------------------------
# composition_render: concurrent actor branch
# --------------------------------------------------------------------------

HEX64 = "a" * 64


def _reviewed_gate(domain="Gate", module="gate"):
    return {
        "schema_version": 2,
        "review_status": "reviewed",
        "domain_name": domain,
        "module_name": module,
        "state_variables": [
            {"kind": "int", "name": "door", "bound": [0, 1], "initial": 0}],
        "operations": [{
            "name": "Open", "return_type": "void", "failure_semantics": "unavailable",
            "guards": [{"id": "g1", "expression": {
                "kind": "eq", "left": {"kind": "field", "name": "door"},
                "right": {"kind": "integer", "value": 0}}}],
            "effects": [{"id": "e1", "target": "door",
                         "value": {"kind": "integer", "value": 1}}],
            "frame": ["door"], "exception_type": None, "exception_trigger": None}],
        "tlc_invariants": [{
            "id": "DoorBound",
            "expression": {"kind": "lte",
                           "left": {"kind": "field", "name": "door"},
                           "right": {"kind": "integer", "value": 1}}}],
        "accepted_candidate_sha256": HEX64,
        "accepted_evidence_sha256": "b" * 64,
    }


def _composition_value():
    return {
        "system_name": "GateSystem",
        "architecture": {
            "name": "GateSystem",
            "description": "gate plus control panel",
            "components": [
                {"id": "gate", "name": "Gate", "layer": "entities", "kind": "class",
                 "operations": [], "dependencies": []},
                {"id": "panel", "name": "Panel", "layer": "use_cases", "kind": "class",
                 "operations": [],
                 "dependencies": [{"target": "gate", "abstraction": True}]},
            ],
            "use_cases": [],
        },
        "bindings": [
            {"component": "gate", "module_name": "gate"},
            {"component": "panel", "module_name": "panel"},
        ],
        "use_cases": [
            {"name": "OpenGate", "steps": [{"component": "gate", "operation": "Open"}]},
            {"name": "PanelOpensGate",
             "steps": [{"component": "panel", "operation": "Open"}]},
        ],
    }


def _v2_dir(tmp_path):
    directory = tmp_path / "v2"
    directory.mkdir()
    (directory / "gate.json").write_text(json.dumps(_reviewed_gate()),
                                         encoding="utf-8")
    (directory / "panel.json").write_text(
        json.dumps(_reviewed_gate(domain="Panel", module="panel")),
        encoding="utf-8")
    return directory


def test_verify_composition_attaches_and_rejects_actor_models(tmp_path):
    v2_dir = _v2_dir(tmp_path)

    # 396-400 (invalid branch): duplicate actor names fail before any verifier run.
    invalid = verify_composition(_composition_value(), v2_dir, actors=["A", "A"])
    assert invalid["status"] == "CONCURRENT_MODEL_INVALID"
    assert invalid["claim"] == "NO_PROOF"

    # 396-400 (ready branch): the model is attached and composition still checks.
    with patch("pipeline.composition_render.verify_files", return_value=(0, "")):
        result = verify_composition(_composition_value(), v2_dir,
                                    run_esc=False, actors=["OrderA", "OrderB"])
    assert result["status"] == "COMPOSITION_CHECKED"
    assert result["claim"] == "STATIC_CHECK"
    assert result["concurrent_model"]["status"] == "CONCURRENT_MODEL_READY"
    assert result["concurrent_model"]["actors"] == ["OrderA", "OrderB"]
    assert result["concurrent_linearizability_proved"] is False
