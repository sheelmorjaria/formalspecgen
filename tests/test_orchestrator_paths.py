import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import orchestrator
from pipeline.llm import LLMError
from pipeline.schemas import SpecDraft, VC


SOURCE = "public class Counter {}"


def test_implementation_router_dispatches_by_extension_and_fails_closed(tmp_path):
    java = tmp_path / "X.java"; java.write_text("public class X {}", encoding="utf-8")
    rust = tmp_path / "X.rs"; rust.write_text("fn x() {}", encoding="utf-8")
    cfile = tmp_path / "X.c"; cfile.write_text("int x(void) {}", encoding="utf-8")
    unknown = tmp_path / "X.txt"; unknown.write_text("x", encoding="utf-8")
    with patch("pipeline.profile.run_assured_implementation", return_value={"kind": "java"}) as java_run:
        assert orchestrator.run_implementation_loop(java, provider="ollama")["kind"] == "java"
        java_run.assert_called_once()
    with patch("pipeline.implementation.synthesize_implementation",
               return_value={"final_status": "VERIFIED"}) as method_run:
        result = orchestrator.run_implementation_loop(
            java, provider="ollama", method_proof_only=True,
            clarifications="ignored", abstraction="atomic_operations")
        assert result["assurance_scope"] == "method_contract_only"
        assert not result["bounded_architecture_checked"]
        assert not result["source_refinement_proved"]
        assert method_run.call_args.kwargs["verification_mode"] == "esc"
    with patch("pipeline.polyglot_implementation.synthesize_polyglot_implementation",
               return_value={"kind": "rust"}) as poly:
        result = orchestrator.run_implementation_loop(
            rust, provider="ollama", assurance_level="standard",
            clarifications="ignored", abstraction="atomic_operations")
        assert result["assurance_level_requested"] == "standard"
        assert result["assurance_note"]
        assert poly.call_args.kwargs["language"] == "rust"
        assert poly.call_args.kwargs["verification_mode"] == "check"
        assert poly.call_args.kwargs["runtime_gate"] is True
    with patch("pipeline.polyglot_implementation.synthesize_polyglot_implementation",
               return_value={"final_status": "STATIC_CHECKED", "claim": "STATIC_CHECK",
                             "runtime_evidence": {
                                 "status": "NO_RUNTIME_FAILURE_FOUND",
                                 "claim": "RUNTIME_SAMPLE"}}):
        sampled = orchestrator.run_implementation_loop(
            rust, provider="ollama", assurance_level="standard")
    assert sampled["final_status"] == "STATIC_CHECKED_RUNTIME_TESTED"
    assert sampled["claim"] == "RUNTIME_SAMPLE"
    with patch("pipeline.polyglot_implementation.synthesize_polyglot_implementation",
               return_value={"kind": "c"}) as poly:
        result = orchestrator.run_implementation_loop(
            cfile, assurance_level="critical", method_proof_only=True)
        assert result["assurance_level_requested"] == "critical"
        assert result["assurance_scope"] == "method_contract_only"
        assert not result["bounded_architecture_checked"]
        assert not result["source_refinement_proved"]
        assert poly.call_args.kwargs["language"] == "c"
        assert poly.call_args.kwargs["verification_mode"] == "esc"
        assert poly.call_args.kwargs["runtime_gate"] is False
    with patch("pipeline.polyglot_implementation.synthesize_polyglot_implementation",
               return_value={"kind": "rust-refinement"}) as poly:
        routed = orchestrator.run_implementation_loop(
            rust, v2_reviewed_domain="reviewed.json",
            v2_validation_evidence="validation.json")
    assert routed["kind"] == "rust-refinement"
    assert poly.call_args.kwargs["v2_reviewed_domain"] == "reviewed.json"
    assert poly.call_args.kwargs["v2_validation_evidence"] == "validation.json"
    assert poly.call_args.kwargs["candidate"] == "fn x() {}"
    with pytest.raises(ValueError, match="unsupported synthesis"):
        orchestrator.run_implementation_loop(unknown)


def test_reviewed_lock_protocol_routes_to_structural_gate_without_synthesis(tmp_path):
    rust = tmp_path / "Lock.rs"; rust.write_text("canonical", encoding="utf-8")
    reviewed = SimpleNamespace(concurrency=object())
    discipline = {"status": "VERIFIED", "claim": "LOCK_DISCIPLINE_VERIFIED",
                  "lock_discipline_proved": True,
                  "source_refinement_proved": False,
                  "concurrent_linearizability_proved": False}
    with patch("pipeline.v2_refinement.load_bound_reviewed_domain",
               return_value=reviewed), \
         patch("pipeline.v2_lock_serializer.lock_discipline_gate",
               return_value=discipline) as gate, \
         patch("pipeline.rust_support.check_rust_syntax",
               return_value={"status": "RUST_CHECKED"}), \
         patch("pipeline.polyglot_implementation.synthesize_polyglot_implementation") as synth:
        result = orchestrator.run_implementation_loop(
            rust, v2_reviewed_domain="reviewed.json",
            v2_validation_evidence="validation.json")
    synth.assert_not_called()
    gate.assert_called_once_with(reviewed, "canonical", "rust")
    assert result["final_status"] == "LOCK_DISCIPLINE_VERIFIED"
    assert result["claims"] == ["BOUNDED_ARCHITECTURE_EVIDENCE",
                                "LOCK_DISCIPLINE_VERIFIED"]
    assert not result["concurrent_linearizability_proved"]


def test_lock_protocol_router_fails_closed_at_each_native_boundary(tmp_path):
    reviewed = SimpleNamespace(concurrency=object())
    rust = tmp_path / "Lock.rs"; rust.write_text("canonical", encoding="utf-8")
    cfile = tmp_path / "Lock.c"; cfile.write_text("canonical", encoding="utf-8")
    java = tmp_path / "Lock.java"; java.write_text("canonical", encoding="utf-8")
    paths = {"v2_reviewed_domain": "reviewed.json",
             "v2_validation_evidence": "validation.json"}

    with patch("pipeline.v2_refinement.load_bound_reviewed_domain",
               return_value=reviewed):
        unsupported = orchestrator.run_implementation_loop(cfile, **paths)
    assert unsupported["code"] == "unsupported_lock_language"
    assert not unsupported["concurrent_linearizability_proved"]

    failed = {"status": "FAIL", "code": "noncanonical_lock_surface",
              "claim": "NO_PROOF"}
    with patch("pipeline.v2_refinement.load_bound_reviewed_domain",
               return_value=reviewed), patch(
                   "pipeline.v2_lock_serializer.lock_discipline_gate",
                   return_value=failed):
        rejected = orchestrator.run_implementation_loop(rust, **paths)
    assert rejected["final_status"] == "LOCK_DISCIPLINE_FAILED"

    discipline = {"status": "VERIFIED", "claim": "LOCK_DISCIPLINE_VERIFIED"}
    with patch("pipeline.v2_refinement.load_bound_reviewed_domain",
               return_value=reviewed), patch(
                   "pipeline.v2_lock_serializer.lock_discipline_gate",
                   return_value=discipline), patch(
                   "pipeline.rust_support.check_rust_syntax",
                   return_value={"status": "RUST_FAILED"}):
        native_failed = orchestrator.run_implementation_loop(rust, **paths)
    assert native_failed["final_status"] == "NATIVE_CHECK_FAILED"
    assert native_failed["claim"] == "NO_PROOF"

    with patch("pipeline.v2_refinement.load_bound_reviewed_domain",
               return_value=reviewed), patch(
                   "pipeline.v2_lock_serializer.lock_discipline_gate",
                   return_value=discipline), patch(
                   "pipeline.validate.check_stub", return_value=(False, ["bad JML"])):
        java_failed = orchestrator.run_implementation_loop(java, **paths)
    assert java_failed["native_check"]["errors"] == ["bad JML"]


def test_usage_slug_and_fallback_helpers():
    assert orchestrator._norm_usage({"prompt_tokens": 2, "completion_tokens": 3}) == {
        "input": 2, "output": 3, "total": 0}
    total = {"input": 1, "output": 1, "total": 2}
    orchestrator._add(total, {"input": 2, "output": 3, "total": 5})
    assert total == {"input": 3, "output": 4, "total": 7}
    assert orchestrator._slug("***") == "spec"
    assert orchestrator._slug("Hello, Formal World!", 12) == "hello-formal"
    assert orchestrator._reviewed_domain_findings("bounded counter", SOURCE) == []
    incompatible = "class TrafficLightController { int nsLight; int ewLight; }"
    findings = orchestrator._reviewed_domain_findings(
        "Design a traffic-light controller", incompatible)
    assert findings[0]["code"] == "domain-contract-mismatch"
    assert "missing reviewed operations" in findings[0]["message"]

    traffic_jml = Path("domains/TrafficLightController.java").read_text(encoding="utf-8")
    assert orchestrator._reviewed_domain_findings(
        "Design a traffic light controller", traffic_jml) == []

    primary = object()
    fallback = object()
    with (patch.object(orchestrator, "_chat_fn", side_effect=[primary, fallback]),
          patch.object(orchestrator, "glm_generate_spec",
                       side_effect=[LLMError("API", "down"), "draft"]) as generate):
        assert orchestrator._gen("nl", None, "glm", "ollama") == "draft"
    assert generate.call_args.kwargs["chat_fn"] is fallback

    with (patch.object(orchestrator, "_chat_fn", return_value=primary),
          patch.object(orchestrator, "glm_generate_spec", side_effect=LLMError("API", "down"))):
        with pytest.raises(LLMError):
            orchestrator._gen("nl", None, "glm", None)


def test_repair_falls_back_to_secondary_provider():
    primary = lambda *_args, **_kwargs: None
    secondary = lambda *_args, **_kwargs: None
    calls = []

    def repair(*args, **kwargs):
        calls.append(kwargs["chat_fn"])
        if len(calls) == 1:
            raise LLMError("API", "down")
        return "fixed"

    with (patch.object(orchestrator, "_chat_fn", side_effect=[primary, secondary]),
          patch.object(orchestrator, "glm_repair_spec", side_effect=repair)):
        assert orchestrator._repair("old", "error", "nl", None, "glm", "ollama") == "fixed"
    assert calls == [primary, secondary]


def test_check_attempt_rejects_invalid_source(tmp_path):
    result = orchestrator._check_attempt(tmp_path, "not java", "Draft")
    assert result[0] == 1 and result[2][0].category == "error"
    assert (tmp_path / "check.log").exists()


def test_check_attempt_javac_failure_timeout_and_missing(tmp_path):
    cases = [
        (SimpleNamespace(returncode=1, stdout="", stderr="syntax bad"), 1, "syntax bad"),
        (subprocess.TimeoutExpired("javac", 1), 124, "timed out"),
        (FileNotFoundError(2, "missing", "javac"), 127, "not found"),
    ]
    for index, (outcome, expected, message) in enumerate(cases):
        root = tmp_path / str(index)
        root.mkdir()
        effect = outcome if isinstance(outcome, BaseException) else None
        with patch.object(orchestrator.subprocess, "run",
                          side_effect=effect, return_value=None if effect else outcome):
            result = orchestrator._check_attempt(root, SOURCE, "Draft")
        assert result[0] == expected and message in result[1]
        gate = json.loads((root / "javac-gate.json").read_text(encoding="utf-8"))
        assert gate["exit_code"] == expected


def test_check_attempt_openjml_diagnostic_fallback(tmp_path):
    compiled = SimpleNamespace(returncode=0, stdout="", stderr="")
    with (patch.object(orchestrator.subprocess, "run", return_value=compiled),
          patch.object(orchestrator, "verify", return_value=(6, "unparsed verifier failure")),
          patch.object(orchestrator, "parse_check", return_value=[])):
        exit_code, text, vcs, path = orchestrator._check_attempt(tmp_path, SOURCE, "Draft")
    assert exit_code == 6 and text == "unparsed verifier failure"
    assert vcs[0].category == "check" and path.name == "Counter.java"


def _mock_check(root, stub, fallback_name, exit_code=0, vcs=None):
    path = Path(root) / "Counter.java"
    path.write_text(stub, encoding="utf-8")
    return exit_code, "diagnostic", vcs or [], path


def test_run_verified_records_events_provenance_and_metadata(tmp_path):
    events = []
    draft = SpecDraft(SOURCE, assumptions=["bounded"], missing_info=["maximum?"])
    with (patch.object(orchestrator, "_gen", return_value=(draft, "model-x", {
              "prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5})),
          patch.object(orchestrator, "_check_attempt", side_effect=_mock_check),
          patch.object(orchestrator, "command_version", return_value="OpenJML test")):
        result = orchestrator.run("counter", out_dir=tmp_path, on_event=events.append)
    assert result.final_status == "VERIFIED"
    assert result.tokens == {"input": 2, "output": 3, "total": 5}
    assert result.assumptions == ["bounded"] and result.missing_info == ["maximum?"]
    assert result.provenance["tool_version"] == "OpenJML test"
    assert any(event["type"] == "verified" for event in events)
    assert (tmp_path / "verdict.json").exists()


def test_run_api_and_tool_failures_are_terminal(tmp_path):
    error = LLMError("NETWORK", "offline", 503)
    with (patch.object(orchestrator, "_gen", side_effect=error),
          patch.object(orchestrator, "command_version", return_value="unavailable")):
        result = orchestrator.run("counter", out_dir=tmp_path / "api")
    assert result.final_status == "API_ERROR" and len(result.attempts) == 1

    draft = SpecDraft(SOURCE)
    vc = VC("Counter.java", 0, "Tool", detail="missing")
    checker = lambda root, stub, fallback_name: _mock_check(root, stub, fallback_name, 127, [vc])
    with (patch.object(orchestrator, "_gen", return_value=(draft, "m", {})),
          patch.object(orchestrator, "_check_attempt", side_effect=checker),
          patch.object(orchestrator, "command_version", return_value="unavailable")):
        result = orchestrator.run("counter", out_dir=tmp_path / "tool")
    assert result.final_status == "TOOL_MISSING"
    assert "repair is disabled" in result.stop_reason


def test_run_resample_then_feedback_and_budget_stop(tmp_path):
    drafts = [SpecDraft(f"public class Counter {{ int n{i}; }}") for i in range(3)]
    vc = VC("Counter.java", 2, "error", detail="different")
    checker = lambda root, stub, fallback_name: _mock_check(root, stub, fallback_name, 1, [vc])
    with (patch.object(orchestrator, "_gen", side_effect=[
              (drafts[0], "m", {}), (drafts[1], "m", {})]) as generate,
          patch.object(orchestrator, "_repair", return_value=(drafts[2], "m", {})) as repair,
          patch.object(orchestrator, "_check_attempt", side_effect=checker),
          patch.object(orchestrator, "command_version", return_value="v")):
        result = orchestrator.run("counter", out_dir=tmp_path,
                                  resample_budget=2, feedback_budget=1, max_attempts=3)
    assert generate.call_count == 2 and repair.call_count == 1
    assert result.final_status == "COMPILE_FAILED"
    assert "max attempts" in result.stop_reason


def test_run_repeated_failure_surfaces_requirement_ambiguity(tmp_path):
    drafts = [SpecDraft(f"public class Counter {{ int n{i}; }}") for i in range(3)]
    vc = VC("Counter.java", 2, "Postcondition", detail="same missing fact")
    checker = lambda root, stub, fallback_name: _mock_check(root, stub, fallback_name, 1, [vc])
    with (patch.object(orchestrator, "_gen", side_effect=[
              (drafts[0], "m", {}), (drafts[1], "m", {})]),
          patch.object(orchestrator, "_repair", return_value=(drafts[2], "m", {})),
          patch.object(orchestrator, "_check_attempt", side_effect=checker),
          patch.object(orchestrator, "command_version", return_value="v")):
        result = orchestrator.run("counter", out_dir=tmp_path,
                                  resample_budget=2, feedback_budget=3, max_attempts=5)
    assert "NL_AMBIGUITY_SUSPECTED" in result.stop_reason


def test_run_javac_evidence_overrides_later_check_result(tmp_path):
    draft = SpecDraft(SOURCE)

    def checker(root, stub, fallback_name):
        path = Path(root) / "Counter.java"
        path.write_text(stub, encoding="utf-8")
        (Path(root) / "javac-gate.json").write_text(
            '{"exit_code": 1, "output": "javac rejected source"}', encoding="utf-8")
        return 0, "check passed", [], path

    with (patch.object(orchestrator, "_gen", return_value=(draft, "m", {})),
          patch.object(orchestrator, "_check_attempt", side_effect=checker),
          patch.object(orchestrator, "command_version", return_value="v")):
        result = orchestrator.run("counter", out_dir=tmp_path,
                                  resample_budget=1, feedback_budget=0, max_attempts=1)
    assert result.final_status == "COMPILE_FAILED"
    assert result.attempts[0].vcs[0].category == "Javac"
