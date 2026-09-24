"""Regressions for the September 2026 assurance-integrity review."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

import mcp_server
from pipeline import cli, implementation
from pipeline.llm import _chat_fn
from pipeline.refactor_gate import _public_contract_clauses
from pipeline.verify import VerificationExecutionResult


CASE_STUB = r'''public class AccessPolicy {
    //@ ensures \result.equals("Admin");
    public String role() { return null; }
}
'''

OWNERSHIP_STUB = r'''public class Pair {
    //@ ensures \result == 1;
    public int first() { return 0; }

    //@ ensures \result == 2;
    public int second() { return 0; }
}
'''


def test_contract_literals_remain_case_sensitive():
    changed = CASE_STUB.replace('"Admin"', '"admin"')
    assert implementation.trusted_surface_matches(CASE_STUB, changed)[0] is False


def test_contract_clauses_remain_owned_by_their_methods():
    changed = (OWNERSHIP_STUB.replace(r"\result == 1", "PLACEHOLDER")
               .replace(r"\result == 2", r"\result == 1")
               .replace("PLACEHOLDER", r"\result == 2"))
    trusted, differences = implementation.trusted_surface_matches(
        OWNERSHIP_STUB, changed)
    assert trusted is False
    assert "members" in differences["clauses"]["expected"]


def test_added_assumption_is_rejected_before_verifier_runs(tmp_path):
    changed = OWNERSHIP_STUB.replace(
        "public int first() { return 0; }",
        "public int first() {\n        //@ assume false;\n        return 0;\n    }",
    )
    with patch.object(implementation, "_javac") as javac, \
         patch.object(implementation, "verify") as verifier:
        result = implementation.synthesize_implementation(
            OWNERSHIP_STUB, candidate=changed, out_dir=tmp_path, max_attempts=1)
    assert result["final_status"] == "TRUST_BOUNDARY_VIOLATION"
    javac.assert_not_called()
    verifier.assert_not_called()


def test_annotated_field_removal_is_a_surface_change():
    changed = OWNERSHIP_STUB.replace(
        "public class Pair {", "public class Pair {\n    private /*@ spec_public @*/ int state;")
    assert implementation.trusted_surface_matches(changed, OWNERSHIP_STUB)[0] is False


def test_refactor_surface_keeps_class_invariants_and_assumptions():
    source = r'''public class Counter {
        //@ public invariant count >= 0;
        private int count;
        public void increment() {
            //@ assume count < 10;
            count++;
        }
    }'''
    clauses = _public_contract_clauses(source)
    assert "public invariant count >= 0" in clauses
    assert "assume count < 10" in clauses


def test_mcp_dropped_java_obligation_never_mints_proof(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("Counter.java").write_text("public class Counter {}", encoding="utf-8")
    with patch("mcp_server.verify_detailed", return_value=VerificationExecutionResult(
            0, "Not implemented for static checking", None)):
        result = mcp_server.verify_code("Counter.java", "esc")
    assert result["status"] == "VACUOUS_VERIFIED"
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False


def test_cli_semantic_failure_with_zero_tool_exit_is_failure(tmp_path):
    source = tmp_path / "counter.c"
    source.write_text("int counter(void) { return 0; }", encoding="utf-8")
    args = SimpleNamespace(source=str(source), mode="esc", backend="prusti", json=None)
    ui = cli.TerminalUI(Console(file=None, force_terminal=False), lambda _: "")
    backend_result = {
        "status": "VERIFY_FAILED", "exit_code": 0, "claim": "NO_PROOF",
        "proved_goals": 3, "total_goals": 4,
    }
    with patch.object(cli, "verify_c", return_value=backend_result):
        assert cli.command_verify(args, ui) == 1


def test_mcp_system_deserializes_and_validates_plan_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", "0")
    for name in ("Service.java", "domain.json", "evidence.json"):
        Path(name).write_text("{}", encoding="utf-8")
    plan = {
        "components": [{
            "component": "service",
            "interface_file": "Service.java",
            "reviewed_domain": "domain.json",
            "validation_evidence": "evidence.json",
        }]
    }
    import json
    Path("plan.json").write_text(json.dumps(plan), encoding="utf-8")
    with patch("pipeline.system_orchestrator.verify_system",
               return_value={"status": "SYSTEM_SYNTHESIS_VERIFIED"}) as verify:
        result = mcp_server.system("plan.json", out_dir="out")
    assert result["status"] == "SYSTEM_SYNTHESIS_VERIFIED"
    parsed = verify.call_args.args[0]
    assert isinstance(parsed, dict)
    assert Path(parsed["components"][0]["interface_file"]).is_absolute()


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError, match="unknown LLM provider"):
        _chat_fn("typo-provider")
