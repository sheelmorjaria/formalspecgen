import subprocess
from types import SimpleNamespace
from unittest.mock import patch
import pytest

from pipeline import c_support
from pipeline.llm import LLMError


VALID = r"""/*@ requires x < 2147483647;
    assigns \nothing;
    ensures \result == x + 1;
*/
int increment(int x) { return x + 1; }
"""


def test_acsl_lint_rejects_unreviewed_c_and_missing_frames():
    findings = c_support.lint_acsl("int f(void) { malloc(2); volatile int x; asm(\"\"); strcpy(0,0); return 0; }")
    codes = {item["code"] for item in findings}
    assert {"acsl-dynamic-memory", "acsl-concurrency", "acsl-assembly",
            "acsl-unsafe-library", "acsl-missing-assigns"} <= codes
    assert c_support.lint_acsl(VALID) == []


def test_acsl_drafting_success_parse_and_api_errors():
    raw = f"```c\n{VALID}```\n```json\n{{\"assumptions\":[\"bounded\"]}}\n```"
    chat = lambda *_args: (raw, "model", {"total_tokens": 3})
    with patch.object(c_support, "_chat_fn", return_value=chat):
        result = c_support.draft_acsl("increment", "ollama")
    assert result["status"] == "DRAFTED" and result["assumptions"] == ["bounded"]
    with patch.object(c_support, "_chat_fn", return_value=lambda *_: ("none", "m", {})):
        assert c_support.draft_acsl("x")["status"] == "PARSE_ERROR"
    malformed = f"```c\n{VALID}```\n```json\nnot-json\n```"
    with patch.object(c_support, "_chat_fn", return_value=lambda *_: (malformed, "m", {})):
        assert c_support.draft_acsl("x")["missing_info_questions"]
    with patch.object(c_support, "_chat_fn", return_value=lambda *_: (_ for _ in ()).throw(LLMError("NETWORK", "down"))):
        assert c_support.draft_acsl("x")["status"] == "API_ERROR"


def test_accepted_c_passes_add_only_reviewable_validity_and_marker_frames():
    code = r"""/*@ assigns \nothing; ensures \result == *input; */
int read(const int *input, int *unused) { return *input; }
int plain(int *p) { return 0; }
// acsl-loop-assigns: i, output[0 .. n-1]
while (i < n) { output[i++] = 0; }
"""
    result = c_support.apply_c_passes(code, ["inject_null_checks", "inject_loop_assigns"])
    assert r"requires \valid_read(input);" in result["code"]
    assert r"\valid(unused)" not in result["code"]
    assert r"\valid(p)" not in result["code"]
    assert "/*@ loop assigns i, output[0 .. n-1]; */" in result["code"]
    assert result["proof_relevant_change"] and result["requires_human_acceptance"]
    assert not result["accepted"] and any(item.get("diff") for item in result["passes"])
    assert not c_support.apply_c_passes(code, [])["changed"]
    with pytest.raises(ValueError, match="unknown C"):
        c_support.apply_c_passes(code, ["guess_aliases"])


def test_c_overflow_pass_derives_exact_int_constant_bounds_and_limits_header():
    code = r"""/*@ assigns \nothing; ensures \result == value + 1; */
int increment(int value) { return value + 1; }
/*@ assigns \nothing; ensures \result == value * 2; */
int twice(int value) { return value * 2; }
"""
    result = c_support.apply_c_passes(code, ["inject_overflow_bounds"])
    assert result["code"].startswith("#include <limits.h>\n")
    assert "requires value <= INT_MAX - 1;" in result["code"]
    assert "requires value >= INT_MIN / 2 && value <= INT_MAX / 2;" in result["code"]
    assert c_support.apply_c_passes(result["code"], ["inject_overflow_bounds"])["code"] == result["code"]

    variants = r"""/*@ assigns \nothing; */
int a(int x) { return x + -2; }
/*@ assigns \nothing; */
int b(int x) { return x - 2; }
/*@ assigns \nothing; */
int c(int x) { return x - -2; }
/*@ assigns \nothing; */
int d(int x) { return x * -2; }
/*@ assigns \nothing; */
int zero(int x) { return x * 0; }
"""
    transformed = c_support.apply_c_passes(variants, ["inject_overflow_bounds"])["code"]
    assert "x >= INT_MIN - (-2)" in transformed
    assert "x >= INT_MIN + 2" in transformed
    assert "x <= INT_MAX + (-2)" in transformed
    assert "x >= INT_MAX / -2 && x <= INT_MIN / -2" in transformed
    assert c_support._attached_contract("int f(void) {}", 0) is None
    assert c_support._matching_c_brace("int f(void) {", 12) is None


def test_framac_gates_and_proof_summary():
    assert c_support.verify_framac("int f(void){return 0;}")["status"] == "ACSL_LINT_FAILED"
    with patch.object(c_support.shutil, "which", return_value=None):
        assert c_support.verify_framac(VALID)["message"].startswith("C compiler")
    with patch.object(c_support.shutil, "which", side_effect=[None, "/bin/gcc"]):
        assert c_support.verify_framac(VALID)["message"].startswith("Frama-C")

    compile_failure = SimpleNamespace(returncode=1, stdout="", stderr="bad C")
    with patch.object(c_support.shutil, "which", side_effect=["/bin/frama-c", "/bin/gcc"]), \
         patch.object(c_support.subprocess, "run", return_value=compile_failure):
        assert c_support.verify_framac(VALID)["status"] == "C_COMPILE_FAILED"

    for output, returncode, status, claim in (
        ("[wp] Proved goals: 4 / 4", 0, "VERIFIED", "DEDUCTIVE_PROOF"),
        ("[wp] Proved goals: 3 / 4", 0, "VERIFY_FAILED", "NO_PROOF"),
        ("no summary", 0, "VERIFY_FAILED", "NO_PROOF"),
        ("[wp] Proved goals: 4 / 4", 1, "VERIFY_FAILED", "NO_PROOF"),
    ):
        compiled = SimpleNamespace(returncode=0, stdout="", stderr="")
        proved = SimpleNamespace(returncode=returncode, stdout=output, stderr="")
        with patch.object(c_support.shutil, "which", side_effect=["/bin/frama-c", "/bin/gcc"]), \
             patch.object(c_support.subprocess, "run", side_effect=[compiled, proved]):
            result = c_support.verify_framac(VALID)
        assert result["status"] == status and result["claim"] == claim

    compiled = SimpleNamespace(returncode=0, stdout="", stderr="")
    proved = SimpleNamespace(returncode=0, stdout=(
        "[wp] Warning: Skipped RTE guards: invalid function pointer calls\n"
        "[wp] Proved goals: 1 / 1"), stderr="")
    with patch.object(c_support.shutil, "which", side_effect=["/bin/frama-c", "/bin/gcc"]), \
         patch.object(c_support.subprocess, "run", side_effect=[compiled, proved]):
        result = c_support.verify_framac(VALID)
    assert result["runtime_errors"] == "PARTIAL" and result["rte_caveats"]


def test_strict_c_syntax_gate_all_outcomes():
    with patch.object(c_support, "lint_acsl", return_value=[{"severity": "error"}]):
        assert c_support.check_c_syntax(VALID)["status"] == "ACSL_LINT_FAILED"
    with patch.object(c_support, "lint_acsl", return_value=[]), \
         patch.object(c_support.shutil, "which", return_value=None):
        assert c_support.check_c_syntax(VALID)["status"] == "TOOL_MISSING"
    for returncode, status in ((0, "C_CHECKED"), (1, "C_COMPILE_FAILED")):
        process = SimpleNamespace(returncode=returncode, stdout="out", stderr="err")
        with patch.object(c_support, "lint_acsl", return_value=[]), \
             patch.object(c_support.shutil, "which", return_value="/bin/gcc"), \
             patch.object(c_support.subprocess, "run", return_value=process) as run:
            result = c_support.check_c_syntax(VALID, timeout=4)
        assert result["status"] == status
        assert run.call_args.kwargs["timeout"] == 4
    with patch.object(c_support, "lint_acsl", return_value=[]), \
         patch.object(c_support.shutil, "which", return_value="/bin/gcc"), \
         patch.object(c_support.subprocess, "run", side_effect=subprocess.TimeoutExpired("gcc", 1)):
        assert c_support.check_c_syntax(VALID)["status"] == "TIMEOUT"
    with patch.object(c_support, "lint_acsl", return_value=[]), \
         patch.object(c_support.shutil, "which", return_value="/bin/gcc"), \
         patch.object(c_support.subprocess, "run", side_effect=OSError("broken")):
        assert c_support.check_c_syntax(VALID)["status"] == "TOOL_ERROR"


def test_framac_timeouts_and_tool_errors():
    tools = patch.object(c_support.shutil, "which", side_effect=["/bin/frama-c", "/bin/gcc"])
    with tools, patch.object(c_support.subprocess, "run", side_effect=subprocess.TimeoutExpired("gcc", 1)):
        assert c_support.verify_framac(VALID)["status"] == "TIMEOUT"
    with patch.object(c_support.shutil, "which", side_effect=["/bin/frama-c", "/bin/gcc"]), \
         patch.object(c_support.subprocess, "run", side_effect=OSError("gcc broken")):
        assert c_support.verify_framac(VALID)["status"] == "TOOL_ERROR"
    compiled = SimpleNamespace(returncode=0, stdout="", stderr="")
    with patch.object(c_support.shutil, "which", side_effect=["/bin/frama-c", "/bin/gcc"]), \
         patch.object(c_support.subprocess, "run", side_effect=[compiled, subprocess.TimeoutExpired("wp", 1)]):
        assert c_support.verify_framac(VALID)["status"] == "TIMEOUT"
    with patch.object(c_support.shutil, "which", side_effect=["/bin/frama-c", "/bin/gcc"]), \
         patch.object(c_support.subprocess, "run", side_effect=[compiled, OSError("wp broken")]):
        assert c_support.verify_framac(VALID)["status"] == "TOOL_ERROR"
