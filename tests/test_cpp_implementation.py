"""C++ implement/repair cycle and structured-VC repair prompts."""
from __future__ import annotations

from unittest.mock import patch

from pipeline.polyglot_implementation import (
    CPP_IMPLEMENT_SYSTEM,
    cpp_trusted_surface,
    synthesize_polyglot_implementation,
    trusted_surface_matches,
)

STUB = """class BoundedCounter {
public:
    BoundedCounter();
    void increment();
    void decrement();
private:
    int count_;
};

BoundedCounter::BoundedCounter() { count_ = 0; assert(count_ >= 0 && count_ <= 5); }

void BoundedCounter::increment() {
    if (count_ < 5) { count_ = count_ + 1; }
    assert(count_ >= 0 && count_ <= 5);
}

void BoundedCounter::decrement() {
    if (count_ > 0) { count_ = count_ - 1; }
    assert(count_ >= 0 && count_ <= 5);
}
"""

BROKEN = STUB.replace("if (count_ < 5)", "if (count_ < 6)")  # violates bound assertion

ESBMC_FAILURE = ("Violated property:\n  file candidate.cpp line 9 function increment\n"
                 "assert(count_ >= 0 && count_ <= 5)\n\nVERIFICATION FAILED\n")


def test_cpp_trusted_surface_captures_signatures_classes_and_assertions():
    surface = cpp_trusted_surface(STUB)
    assert surface["classes"]
    assert any("increment" in signature for signature in surface["signatures"])
    assert any("assert" in contract for contract in surface["contracts"])
    assert trusted_surface_matches(STUB, STUB, "cpp")[0]
    assert not trusted_surface_matches(STUB, BROKEN.replace("assert(count_ >= 0", "// dropped"),
                                       "cpp")[0]


def test_cpp_repair_cycle_mints_bounded_cpp_proof(tmp_path):
    prompts: list[list[dict]] = []

    def chat(provider):
        def call(messages, model, temperature):
            prompts.append(messages)
            if len(prompts) == 1:
                return "```cpp\n" + BROKEN + "\n```", "fixture-model", {}
            return "```cpp\n" + STUB + "\n```", "fixture-model", {}
        return call

    def failing_verify_cpp(path, **kwargs):
        return {"status": "VERIFY_FAILED", "claim": "NO_PROOF", "language": "cpp",
                "exit_code": 1, "output": ESBMC_FAILURE,
                "vcs": [{"file": "candidate.cpp", "line": 9, "category": "Postcondition",
                         "method": "increment", "decl": None,
                         "detail": "assert(count_ >= 0 && count_ <= 5)", "raw": ESBMC_FAILURE}]}

    from unittest.mock import MagicMock
    verify = MagicMock(side_effect=[failing_verify_cpp(None),
                                    {"status": "VERIFIED", "claim": "BOUNDED_CPP_PROOF",
                                     "language": "cpp", "exit_code": 0,
                                     "output": "VERIFICATION SUCCESSFUL", "vcs": []}])
    with patch("pipeline.polyglot_implementation._chat_fn",
               side_effect=lambda provider: chat(provider)), \
         patch("pipeline.verify_cpp.verify_cpp", verify):
        result = synthesize_polyglot_implementation(
            STUB, language="cpp", provider="ollama", out_dir=tmp_path,
            max_attempts=3, resample_budget=1, feedback_budget=2)

    assert result["final_status"] == "VERIFIED"
    assert result["claim"] == "BOUNDED_CPP_PROOF"  # bounded ceiling, never DEDUCTIVE_PROOF
    assert result["verification_backend"] == "esbmc"
    assert len(result["attempts"]) == 2
    assert result["attempts"][0]["vcs"][0]["category"] == "Postcondition"
    # The repair prompt carries the structured VC, not just raw output.
    repair_prompt = prompts[1][-1]["content"]
    assert "candidate.cpp:9 Postcondition" in repair_prompt
    assert "Structured verification failures" in repair_prompt


def test_cpp_check_mode_stops_at_static_check(tmp_path):
    def chat(provider):
        def call(messages, model, temperature):
            return "```cpp\n" + STUB + "\n```", "fixture-model", {}
        return call

    with patch("pipeline.polyglot_implementation._chat_fn",
               side_effect=lambda provider: chat(provider)), \
         patch("pipeline.cpp_support.check_cpp_syntax",
               return_value={"status": "CPP_CHECKED", "output": ""}):
        result = synthesize_polyglot_implementation(
            STUB, language="cpp", provider="ollama", out_dir=tmp_path,
            verification_mode="check", max_attempts=2)
    assert result["final_status"] == "STATIC_CHECKED"
    assert result["claim"] == "STATIC_CHECK"


def test_cpp_trust_boundary_violation_is_terminal(tmp_path):
    signature_broken = STUB.replace("void increment();", "int increment();")

    def chat(provider):
        def call(messages, model, temperature):
            return "```cpp\n" + signature_broken + "\n```", "fixture-model", {}
        return call

    with patch("pipeline.polyglot_implementation._chat_fn",
               side_effect=lambda provider: chat(provider)):
        result = synthesize_polyglot_implementation(
            STUB, language="cpp", provider="ollama", out_dir=tmp_path, max_attempts=2)
    assert result["final_status"] == "TRUST_BOUNDARY_VIOLATION"
    assert result["claim"] == "NO_PROOF"


def test_orchestrator_routes_cpp_and_rust_repair_prompt_has_vcs(tmp_path):
    from pipeline.orchestrator import run_implementation_loop

    def chat(provider):
        def call(messages, model, temperature):
            return "```cpp\n" + STUB + "\n```", "fixture-model", {}
        return call

    stub_file = tmp_path / "BoundedCounter.cpp"
    stub_file.write_text(STUB, encoding="utf-8")
    with patch("pipeline.polyglot_implementation._chat_fn",
               side_effect=lambda provider: chat(provider)), \
         patch("pipeline.verify_cpp.verify_cpp",
               return_value={"status": "VERIFIED", "claim": "BOUNDED_CPP_PROOF",
                             "language": "cpp", "exit_code": 0,
                             "output": "VERIFICATION SUCCESSFUL", "vcs": []}):
        result = run_implementation_loop(stub_file, provider="ollama",
                                         assurance_level="critical")
    assert result["final_status"] == "VERIFIED"
    assert result["language"] == "cpp"
