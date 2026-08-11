import subprocess
from types import SimpleNamespace
from unittest.mock import patch

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
