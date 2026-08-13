from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline import implementation
from pipeline.llm import LLMError


STUB = r"""public class Counter {
    private /*@ spec_public @*/ int value;
    //@ public invariant value >= 0;

    //@ requires amount > 0;
    //@ assignable value;
    //@ ensures value == \old(value) + amount;
    public void add(int amount) { }
}
"""

CANDIDATE = STUB.replace("public void add(int amount) { }", """public void add(int amount) {
        value += amount;
    }""")


def test_trusted_surface_allows_body_changes_only():
    assert implementation.trusted_surface_matches(STUB, CANDIDATE) == (True, {})
    changed = CANDIDATE.replace("amount > 0", "amount >= 0")
    trusted, diff = implementation.trusted_surface_matches(STUB, changed)
    assert not trusted and "clauses" in diff
    changed_signature = CANDIDATE.replace("add(int amount)", "add(long amount)")
    trusted, diff = implementation.trusted_surface_matches(STUB, changed_signature)
    assert not trusted and "methods" in diff
    with_invariant = CANDIDATE.replace(
        "value += amount;", "//@ loop_invariant value >= 0;\n        value += amount;")
    assert implementation.trusted_surface_matches(STUB, with_invariant)[0]


def test_complete_contract_hash_binds_encapsulation_and_api_surface():
    original = implementation.trusted_surface_hash(STUB)
    assert original == implementation.trusted_surface_hash(CANDIDATE)
    assert original != implementation.trusted_surface_hash(
        STUB.replace("private /*@ spec_public @*/ int value", "public int value"))
    assert original != implementation.trusted_surface_hash(
        STUB.replace("add(int amount)", "add(long amount)"))
    with_getter = STUB.replace("\n}\n", """
    //@ ensures \\result == value;
    public /*@ pure @*/ int getValue() { return value; }
}
""")
    assert implementation.trusted_surface_hash(with_getter) != original
    trusted, differences = implementation.trusted_surface_matches(
        with_getter, with_getter.replace(
            "public /*@ pure @*/ int getValue() { return value; }", ""))
    assert not trusted and "methods" in differences


def test_chat_prompts_use_local_provider_transport():
    chat = lambda messages, model, temperature: (messages[-1]["content"], model, {})
    with patch.object(implementation, "_chat_fn", return_value=chat):
        generated = implementation._chat_generate(STUB, "m", "ollama")
        repaired = implementation._chat_repair(STUB, CANDIDATE, "failed VC", "m", "ollama")
    assert "Trusted JML scaffold" in generated[0]
    assert "Previous candidate" in repaired[0] and "failed VC" in repaired[0]
    assert "InvariantExit" in implementation.REPAIR_SYSTEM
    assert "field mentioned by the associated invariant" in implementation.REPAIR_SYSTEM


def test_native_candidate_verifies_without_external_handoff(tmp_path):
    events = []
    with patch.object(implementation, "_javac", return_value=(0, "compiled")), \
         patch.object(implementation, "verify", return_value=(0, "proved")), \
         patch.object(implementation, "has_dropped_vc", return_value=False):
        result = implementation.synthesize_implementation(
            STUB, candidate=CANDIDATE, out_dir=tmp_path, max_attempts=1,
            resample_budget=1, feedback_budget=0, on_event=events.append)
    assert result["final_status"] == "VERIFIED"
    assert result["claim"] == "DEDUCTIVE_PROOF"
    assert result["native_synthesis"] and not result["external_handoff_used"]
    assert result["implementation_code"] == CANDIDATE
    assert Path(result["implementation_path"]).exists()
    assert (tmp_path / "verdict.json").exists()
    assert any(event["type"] == "implementation_attempt" for event in events)


def test_nonproof_verification_modes_are_labelled_without_proof(tmp_path):
    with patch.object(implementation, "_javac", return_value=(0, "compiled")), \
         patch.object(implementation, "verify", return_value=(0, "checked")) as checked:
        static = implementation.synthesize_implementation(
            STUB, candidate=CANDIDATE, out_dir=tmp_path / "check", max_attempts=1,
            verification_mode="check")
    assert static["final_status"] == "STATIC_CHECKED"
    assert static["claim"] == "STATIC_CHECK"
    assert checked.call_args.kwargs["mode"] == "check"

    with patch.object(implementation, "_javac", return_value=(0, "compiled")), \
         patch.object(implementation, "verify") as verifier:
        compiled = implementation.synthesize_implementation(
            STUB, candidate=CANDIDATE, out_dir=tmp_path / "compile", max_attempts=1,
            verification_mode="compile")
    assert compiled["final_status"] == "COMPILED"
    assert compiled["claim"] == "STATIC_CHECK"
    verifier.assert_not_called()
    with pytest.raises(ValueError, match="verification_mode"):
        implementation.synthesize_implementation(STUB, verification_mode="unknown")


def test_contract_modification_is_terminal_before_tools(tmp_path):
    changed = CANDIDATE.replace("amount > 0", "amount >= 0")
    with patch.object(implementation, "_javac") as javac, patch.object(implementation, "verify") as verify:
        result = implementation.synthesize_implementation(
            STUB, candidate=changed, out_dir=tmp_path, max_attempts=1)
    assert result["final_status"] == "TRUST_BOUNDARY_VIOLATION"
    assert result["claim"] == "NO_PROOF"
    javac.assert_not_called(); verify.assert_not_called()


def test_compile_failure_and_vacuous_proof_are_not_claims(tmp_path):
    with patch.object(implementation, "_javac", return_value=(1, "type error")), \
         patch.object(implementation, "parse_check", return_value=[]):
        failed = implementation.synthesize_implementation(
            STUB, candidate=CANDIDATE, out_dir=tmp_path / "compile", max_attempts=1)
    assert failed["final_status"] == "COMPILE_FAILED" and failed["claim"] == "NO_PROOF"

    with patch.object(implementation, "_javac", return_value=(0, "")), \
         patch.object(implementation, "verify", return_value=(0, "dropped")), \
         patch.object(implementation, "has_dropped_vc", return_value=True):
        vacuous = implementation.synthesize_implementation(
            STUB, candidate=CANDIDATE, out_dir=tmp_path / "vacuous", max_attempts=1)
    assert vacuous["final_status"] == "VACUOUS_VERIFIED"
    assert vacuous["claim"] == "NO_PROOF"


def test_api_error_and_invalid_stub_fail_closed(tmp_path):
    assert implementation.synthesize_implementation("interface X {}") ["final_status"] == "INVALID_STUB"
    with patch.object(implementation, "_chat_generate", side_effect=LLMError("NETWORK", "offline")):
        result = implementation.synthesize_implementation(
            STUB, out_dir=tmp_path, max_attempts=1, resample_budget=1, feedback_budget=0)
    assert result["final_status"] == "API_ERROR"


def test_javac_normalizes_timeout_and_missing_tool(tmp_path):
    source = tmp_path / "C.java"; source.write_text("class C {}", encoding="utf-8")
    import subprocess
    with patch.object(implementation.subprocess, "run", side_effect=subprocess.TimeoutExpired("javac", 1)):
        assert implementation._javac(source, 1)[0] == 124
    with patch.object(implementation.subprocess, "run", side_effect=FileNotFoundError):
        assert implementation._javac(source)[0] == 127
    completed = type("Completed", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
    with patch.object(implementation.subprocess, "run", return_value=completed) as run:
        assert implementation._javac(source) == (0, "ok")
    assert Path(run.call_args.args[0][-1]).is_absolute()
    assert run.call_args.kwargs["cwd"] == str(source.parent.resolve())


def test_generation_repair_empty_and_accepted_pass_paths(tmp_path):
    with patch.object(implementation, "_chat_generate", return_value=("", "m", {})):
        empty = implementation.synthesize_implementation(
            STUB, out_dir=tmp_path / "empty", max_attempts=1,
            resample_budget=1, feedback_budget=0)
    assert empty["final_status"] == "GEN_EMPTY"

    repaired = CANDIDATE.replace("value += amount;", "value = value + amount;")
    with patch.object(implementation, "_chat_generate", return_value=(CANDIDATE, "m", {})), \
         patch.object(implementation, "_chat_repair", return_value=(repaired, "m", {})) as repair, \
         patch.object(implementation, "_javac", return_value=(0, "")), \
         patch.object(implementation, "verify", side_effect=[(6, "failed VC"), (0, "proved")]), \
         patch.object(implementation, "parse_vcs", return_value=[]), \
         patch.object(implementation, "has_dropped_vc", return_value=False), \
         patch.object(implementation, "apply_passes", return_value={
             "code": repaired, "changed": False, "passes": []}) as passes:
        result = implementation.synthesize_implementation(
            STUB, out_dir=tmp_path / "repair", max_attempts=2,
            resample_budget=1, feedback_budget=1, accepted_passes=["inject_pure"])
    assert result["final_status"] == "VERIFIED"
    assert len(result["attempts"]) == 2 and repair.call_count == 1
    assert passes.call_count == 2
    assert result["attempts"][-1]["postprocess"]["accepted"] is True


def test_native_cli_exit_codes(tmp_path, monkeypatch, capsys):
    stub = tmp_path / "Counter.java"
    stub.write_text(STUB, encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        ["implementation", str(stub), "--provider", "ollama", "--max-attempts", "2"],
    )
    with patch.object(
        implementation,
        "synthesize_implementation",
        return_value={"final_status": "VERIFIED"},
    ) as synthesize, pytest.raises(SystemExit) as stopped:
        implementation.main()
    assert stopped.value.code == 0
    assert '"final_status": "VERIFIED"' in capsys.readouterr().out
    assert synthesize.call_args.args[:3] == (STUB, "ollama", None)

    monkeypatch.setattr("sys.argv", ["implementation", str(stub)])
    with patch.object(
        implementation,
        "synthesize_implementation",
        return_value={"final_status": "COMPILE_FAILED"},
    ), pytest.raises(SystemExit) as stopped:
        implementation.main()
    assert stopped.value.code == 1
