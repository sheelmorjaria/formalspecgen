import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import rust_support as rust
from pipeline.llm import LLMError
from pipeline.schemas import VC


def _chat(raw):
    return lambda *_args: (raw, "model", {})


def test_draft_rust_api_parse_and_metadata_paths():
    with patch.object(rust, "_chat_fn", return_value=lambda *_: (_ for _ in ()).throw(
            LLMError("NETWORK", "offline"))):
        assert rust.draft_rust("counter")["status"] == "API_ERROR"

    with patch.object(rust, "_chat_fn", return_value=_chat("no fence")):
        assert rust.draft_rust("counter")["status"] == "PARSE_ERROR"

    raw = """```rust
pub trait Counter { fn value(&self) -> i32; }
```
```json
not-json
```"""
    with (patch.object(rust, "_chat_fn", return_value=_chat(raw)),
          patch.object(rust, "check_rust_syntax", return_value={"status": "RUST_CHECKED"}),
          patch.object(rust, "_prusti_binary", return_value=None)):
        result = rust.draft_rust("counter")
    assert result["status"] == "RUST_CHECKED"
    assert result["verification_status"] == "NOT_RUN"
    assert "malformed metadata" in result["missing_info_questions"][0]


def test_draft_rust_uses_prusti_result_and_valid_metadata():
    raw = """```rust
#[ensures(result >= 0)]
pub fn value() -> i32 { 0 }
```
```json
{"assumptions": ["bounded"], "missing_info_questions": []}
```"""
    with (patch.object(rust, "_chat_fn", return_value=_chat(raw)),
          patch.object(rust, "check_rust_syntax", return_value={"status": "RUST_CHECKED"}),
          patch.object(rust, "_prusti_binary", return_value=Path("prusti")),
          patch.object(rust, "verify_prusti", return_value={"status": "VERIFIED"})):
        result = rust.draft_rust("counter")
    assert result["status"] == "VERIFIED"
    assert result["assumptions"] == ["bounded"]


def test_draft_rust_without_metadata_uses_reviewed_defaults():
    raw = """```rust
pub fn value() -> i32 { 0 }
```"""
    with (patch.object(rust, "_chat_fn", return_value=_chat(raw)),
          patch.object(rust, "check_rust_syntax", return_value={"status": "RUST_CHECKED"}),
          patch.object(rust, "_prusti_binary", return_value=None)):
        result = rust.draft_rust("counter")
    assert result["assumptions"] == []
    assert result["missing_info_questions"] == []


def test_lint_rust_reports_safety_contract_and_idiom_findings():
    code = """#[requires(helper(x))]
pub fn api(values: Vec<i32>, x: usize) -> i32 {
    unsafe { panic!("bad") }
    let p: *const i32 = std::ptr::null();
    let y = values[x].clone().unwrap();
    while x > 0 { todo!() }
    helper(x)
}
fn helper(x: usize) -> bool { x > 0 }
"""
    names = {item["code"] for item in rust.lint_rust(code)}
    assert {"rust-unsafe", "rust-panic-path", "rust-null", "rust-clone",
            "rust-indexing", "rust-missing-postcondition", "rust-contract-vec",
            "rust-missing-loop-invariant", "rust-missing-pure"} <= names

    guarded_loop = "body_invariant!(i <= n);\nwhile i < n { i += 1; }"
    assert "rust-missing-loop-invariant" not in {
        item["code"] for item in rust.lint_rust(guarded_loop)}


def test_apply_rust_passes_is_transparent_and_requires_acceptance():
    code = """// prusti-requires: amount <= 100
#[ensures(sum(values) >= 0)]
pub fn read(values: &[i32], index: usize) -> i32 { values[index] }
fn sum(values: &[i32]) -> i32 { 0 }
"""
    result = rust.apply_rust_passes(code)
    assert result["changed"] and result["proof_relevant_change"]
    assert result["requires_human_acceptance"] and not result["accepted"]
    assert "#[requires(amount <= 100)]" in result["code"]
    assert "#[requires(index < values.len())]" in result["code"]
    assert "#[pure]" in result["code"]
    assert any(item.get("diff") for item in result["passes"] if item["changed"])

    unchanged = rust.apply_rust_passes("fn private() {}", selected=[])
    assert not unchanged["changed"]
    with pytest.raises(ValueError, match="unknown Rust"):
        rust.apply_rust_passes("", ["invent_proof"])

    selected = rust.apply_rust_passes(
        "// prusti-requires: amount <= 10\nfn f() {}", ["inject_overflow_bounds"])
    assert [item["name"] for item in selected["passes"]] == ["inject_overflow_bounds"]


def test_matching_brace_handles_nested_and_unclosed_bodies():
    text = "fn f() { if true { 1 } else { 2 } }"
    opening = text.index("{")
    assert rust._matching_brace(text, opening) == len(text) - 1
    assert rust._matching_brace("fn f() {", 7) is None


def test_check_rust_syntax_success_failure_missing_and_timeout():
    seen = {}

    def run(command, **kwargs):
        seen["command"] = command
        seen.update(kwargs)
        source = Path(command[-1]).read_text(encoding="utf-8")
        assert "prusti_contracts" not in source and "#[ensures" not in source
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    code = "use prusti_contracts::*;\n#[ensures(result > 0)]\npub fn f() -> i32 { 1 }"
    with patch.object(rust.subprocess, "run", side_effect=run):
        result = rust.check_rust_syntax(code, timeout=7)
    assert result["status"] == "RUST_CHECKED" and result["exit_code"] == 0
    assert seen["timeout"] == 7 and seen["command"][0] == "rustc"
    assert result["disclaimer"].endswith("no contract was proved.")

    with patch.object(rust.subprocess, "run", return_value=SimpleNamespace(
            returncode=1, stdout="", stderr="type error")):
        assert rust.check_rust_syntax("fn f() {}")["status"] == "RUST_CHECK_FAILED"
    with patch.object(rust.subprocess, "run", side_effect=FileNotFoundError):
        assert rust.check_rust_syntax("fn f() {}")["status"] == "TOOL_MISSING"
    with patch.object(rust.subprocess, "run", side_effect=subprocess.TimeoutExpired("rustc", 1)):
        assert rust.check_rust_syntax("fn f() {}")["status"] == "TIMEOUT"


def test_verify_prusti_all_outcomes_and_diagnostics(tmp_path):
    with patch.object(rust, "_prusti_binary", return_value=None):
        assert rust.verify_prusti("fn f() {}")["status"] == "TOOL_MISSING"

    binary = tmp_path / "prusti-rustc"
    binary.write_text("", encoding="utf-8")
    vc = VC("contract.rs", 2, "Postcondition", detail="failed")
    completed = SimpleNamespace(returncode=1, stdout="verify error", stderr="")
    with (patch.object(rust, "_prusti_binary", return_value=binary),
          patch.object(rust.subprocess, "run", return_value=completed) as run,
          patch.object(rust, "parse_prusti_vcs", return_value=[vc])):
        result = rust.verify_prusti("fn f() {}", timeout=9)
    assert result["status"] == "VERIFY_FAILED" and result["vcs"][0]["line"] == 2
    assert run.call_args.kwargs["cwd"] == binary.parent
    assert run.call_args.kwargs["timeout"] == 9

    with (patch.object(rust, "_prusti_binary", return_value=binary),
          patch.object(rust.subprocess, "run", return_value=SimpleNamespace(
              returncode=0, stdout="verified", stderr="")),
          patch.object(rust, "parse_prusti_vcs", return_value=[])):
        assert rust.verify_prusti("fn f() {}")["status"] == "VERIFIED"
    with (patch.object(rust, "_prusti_binary", return_value=binary),
          patch.object(rust.subprocess, "run", side_effect=subprocess.TimeoutExpired("p", 1))):
        assert rust.verify_prusti("fn f() {}", timeout=3)["status"] == "TIMEOUT"
    with (patch.object(rust, "_prusti_binary", return_value=binary),
          patch.object(rust.subprocess, "run", side_effect=OSError("cannot execute"))):
        assert rust.verify_prusti("fn f() {}")["status"] == "TOOL_ERROR"


def test_prusti_binary_prefers_configured_then_path(tmp_path):
    configured = tmp_path / "configured-prusti"
    configured.write_text("", encoding="utf-8")
    with patch.object(rust.config, "PRUSTI_BIN", str(configured)):
        assert rust._prusti_binary() == configured.resolve()
    discovered = tmp_path / "path-prusti"
    with (patch.object(rust.config, "PRUSTI_BIN", "prusti-rustc"),
          patch.object(rust.shutil, "which", return_value=str(discovered))):
        assert rust._prusti_binary() == discovered.resolve()
    with (patch.object(rust.config, "PRUSTI_BIN", "missing-prusti"),
          patch.object(rust.shutil, "which", return_value=None)):
        assert rust._prusti_binary() is None
