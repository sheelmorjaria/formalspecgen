"""Coverage backfill for CLI handlers wired since v1.0.0 (analyze/document/correct/etc.)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from pipeline import cli


def _ui():
    return cli.TerminalUI(Console(file=__import__("io").StringIO(), force_terminal=False),
                          lambda _prompt: "answer")


def _draft_args(**overrides):
    base = dict(requirement="counter", provider="ollama", model=None, no_clarify=True,
                lang="java", canonical_domain=None, out_file=None, fallback_provider=None,
                out=None, max_attempts=None, resample_budget=None, feedback_budget=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_analyze_codebase_command_extracts(tmp_path, monkeypatch):
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "SafeCounter.java").write_text(
        "public class SafeCounter { private int count; "
        "public void inc() { if (count < 5) { count = count + 1; } } }", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["analyze-codebase", "legacy", "--out-dir", "extracted",
                     "--project-root", str(tmp_path),
                     "--json", str(tmp_path / "verdict.json")]) == 0
    verdict = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["status"] == "EXTRACTED"


def test_correct_behavior_command_success_and_failure(tmp_path):
    target = tmp_path / "Service.java"
    target.write_text("public class Service {}", encoding="utf-8")
    good = {"status": "BEHAVIOR_CORRECTION_VERIFIED", "claim": "BEHAVIOR_CORRECTION_VERIFIED"}
    bad = {"status": "CORRECTION_FAILED", "claim": "NO_PROOF"}
    with patch("pipeline.behavior_correction.correct_behavior", return_value=good):
        assert cli.main(["correct-behavior", str(target), "--cwe", "CWE-125",
                         "--out-dir", str(tmp_path / "c1"), "--json",
                         str(tmp_path / "v1.json")]) == 0
    with patch("pipeline.behavior_correction.correct_behavior", return_value=bad):
        assert cli.main(["correct-behavior", str(target), "--cwe", "CWE-476",
                         "--out-dir", str(tmp_path / "c2"), "--json",
                         str(tmp_path / "v2.json")]) == 1
    assert json.loads((tmp_path / "v2.json").read_text(encoding="utf-8"))["status"] == "CORRECTION_FAILED"


def test_verify_bisimulation_command_ready_and_not(tmp_path):
    ready = {"status": "BISIMULATION_PREFLIGHT_READY", "claim": "NO_PROOF"}
    not_ready = {"status": "MAPPING_INVALID", "claim": "NO_PROOF"}
    with patch("pipeline.bisimulation.verify_bisimulation_inputs", return_value=ready):
        assert cli.main(["verify-bisimulation", "a.java", "b/", "m.json",
                         "--json", str(tmp_path / "v1.json")]) == 0
    with patch("pipeline.bisimulation.verify_bisimulation_inputs", return_value=not_ready):
        assert cli.main(["verify-bisimulation", "a.java", "b/", "m.json",
                         "--json", str(tmp_path / "v2.json")]) == 1


def test_validate_architecture_command_paths(tmp_path):
    artifact = tmp_path / "architecture.json"
    artifact.write_text(json.dumps({"name": "S", "components": [
        {"name": "Core", "type": "core",
         "state_variables": [{"name": "stock", "type": "int", "bound": [0, 5], "initial": 2}],
         "operations": [{"name": "reserve", "params": [],
                         "contract": {"requires": "stock > 0", "ensures": "true"}}],
         "transitions": []}]}), encoding="utf-8")
    verified = {"status": "VERIFIED", "states": 6, "transitions": 10}
    with patch("pipeline.cli.validate_architecture_with_tlc", return_value=verified):
        assert cli.main(["validate-architecture", str(artifact),
                         "--json", str(tmp_path / "v1.json")]) == 0
    with patch("pipeline.cli.validate_architecture_with_tlc",
               return_value={"status": "DEADLOCK"}):
        assert cli.main(["validate-architecture", str(artifact),
                         "--json", str(tmp_path / "v2.json")]) == 1
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cli.main(["validate-architecture", str(broken)]) == 1


def test_unified_system_command_exit_codes(tmp_path):
    with patch("pipeline.unified_system_runner.run_unified_system",
               return_value={"status": "LOWERED", "claim": "SYSTEM_COMPOSITION_PROOF"}):
        assert cli.main(["unified-system", "arch.json", "--evidence", "ev.json",
                         "--out-dir", str(tmp_path / "out"),
                         "--json", str(tmp_path / "v1.json")]) == 0
    with patch("pipeline.unified_system_runner.run_unified_system",
               return_value={"status": "FAIL", "claim": "NO_PROOF"}):
        assert cli.main(["unified-system", "arch.json", "--evidence", "ev.json",
                         "--out-dir", str(tmp_path / "out2")]) == 1


def test_optimize_algorithm_failure_prints_diagnostics(tmp_path):
    source = tmp_path / "TwoSum.java"
    source.write_text("public class TwoSum {}", encoding="utf-8")
    failure = {"status": "FAIL", "claim": "NO_PROOF", "code": "ESC_FAILED",
               "message": "postcondition violated"}
    with patch("pipeline.algorithm_optimization.optimize_algorithm", return_value=failure):
        assert cli.main(["optimize-algorithm", str(source), "--strategy", "hashmap",
                         "--out", str(tmp_path / "out.java"), "--json",
                         str(tmp_path / "v.json")]) == 1
    assert json.loads((tmp_path / "v.json").read_text(encoding="utf-8"))["code"] == "ESC_FAILED"


def test_promote_domain_v2_prints_signature_line(tmp_path):
    reviewed = SimpleNamespace(accepted_candidate_sha256="a" * 64)
    args = ["promote-domain", "counter", "--project-root", str(tmp_path),
            "--schema-version", "2", "--accept-candidate-sha256", "a" * 64,
            "--signing-key", "KEYID"]
    with patch.object(cli, "promote_validated_candidate", return_value=reviewed):
        assert cli.main(args) == 0


def test_draft_routes_canonical_cpp_and_c(tmp_path, monkeypatch):
    reviewed_dir = tmp_path / "domains" / "v2"
    reviewed_dir.mkdir(parents=True)
    (reviewed_dir / "counter.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    cpp_ns = SimpleNamespace(module_name="counter", domain_name="Counter",
                             accepted_candidate_sha256="a" * 64,
                             accepted_evidence_sha256="b" * 64)
    with patch("pipeline.v2_cpp_serializer.render_reviewed_v2_cpp_file",
               return_value=(cpp_ns, "class Counter {};")), \
         patch("pipeline.cpp_support.check_cpp_syntax",
               return_value={"status": "CPP_CHECKED"}):
        assert cli.main(["draft", "counter", "--lang", "cpp", "--no-clarify",
                         "--canonical-domain", "counter", "--out-file",
                         str(tmp_path / "Counter.cpp")]) == 0
    assert (tmp_path / "Counter.cpp").read_text(encoding="utf-8") == "class Counter {};"

    c_ns = SimpleNamespace(module_name="counter", domain_name="counter",
                           accepted_candidate_sha256="a" * 64,
                           accepted_evidence_sha256="b" * 64)
    with patch("pipeline.v2_acsl_serializer.render_reviewed_v2_acsl_file",
               return_value=(c_ns, "typedef struct { int counter; } counter_state;")), \
         patch("pipeline.c_support.lint_acsl", return_value=[]), \
         patch("pipeline.c_support.check_c_syntax", return_value={"status": "C_CHECKED"}):
        assert cli.main(["draft", "counter", "--lang", "c", "--no-clarify",
                         "--canonical-domain", "counter", "--out-file",
                         str(tmp_path / "counter.c")]) == 0
    evidence = json.loads((tmp_path / "counter.c.canonical.json").read_text(encoding="utf-8"))
    assert evidence["transformation"] == "DETERMINISTIC_V2_TO_ACSL"


def test_reviewed_v2_jml_draft_records_lock_discipline(tmp_path):
    reviewed_dir = tmp_path / "domains" / "v2"
    reviewed_dir.mkdir(parents=True)
    (reviewed_dir / "bank.json").write_text("{}", encoding="utf-8")
    reviewed = SimpleNamespace(module_name="bank", domain_name="Bank",
                               accepted_candidate_sha256="a" * 64,
                               accepted_evidence_sha256="b" * 64,
                               concurrency={"mode": "lock_protocol"})
    discipline = {"claim": "LOCK_DISCIPLINE_VERIFIED", "lock_discipline_proved": True}
    destination = tmp_path / "Bank.java"
    args = _draft_args(lang="java", canonical_domain="bank", out_file=str(destination))
    store = cli.SessionStore(tmp_path)
    state = store.empty()
    with patch("pipeline.v2_jml_serializer.render_reviewed_v2_file",
               return_value=(reviewed, "public class Bank {}")), \
         patch("pipeline.validate.check_stub", return_value=(True, [])), \
         patch("pipeline.v2_lock_serializer.lock_discipline_gate", return_value=discipline):
        assert cli.command_draft(args, _ui(), store, state) == 0
    evidence = json.loads(destination.with_suffix(
        ".java.canonical.json").read_text(encoding="utf-8"))
    assert evidence["claim"] == "LOCK_DISCIPLINE_VERIFIED"
    assert evidence["lock_discipline_proved"] is True
    assert evidence["concurrent_linearizability_proved"] is False


def test_canonical_rust_async_transport_and_safe_identifier(tmp_path):
    from pipeline.canonical_draft import canonical_draft_rust
    reviewed_dir = tmp_path / "domains" / "v2"
    reviewed_dir.mkdir(parents=True)
    (reviewed_dir / "transport.json").write_text("{}", encoding="utf-8")

    try:
        canonical_draft_rust("bad-name", "transport", domains_root=reviewed_dir)
    except ValueError as exc:
        assert "safe module" in str(exc)
    else:
        raise AssertionError("unsafe identifier must be rejected")

    reviewed = SimpleNamespace(module_name="transport", domain_name="Transport",
                               accepted_candidate_sha256="a" * 64,
                               accepted_evidence_sha256="b" * 64,
                               execution_model="async_message_passing", concurrency=None)
    with patch("pipeline.v2_prusti_serializer.render_reviewed_v2_prusti_file",
               return_value=(reviewed, "pub struct Transport {}")), \
         patch("pipeline.rust_support.lint_rust", return_value=[]), \
         patch("pipeline.v2_async_serializer.check_tokio_scaffold",
               return_value={"status": "TOKIO_CHECKED"}):
        result = canonical_draft_rust("transport", "transport", domains_root=reviewed_dir,
                                      out_file=tmp_path / "Transport.rs")
    assert result["evidence"]["transformation"] == "DETERMINISTIC_V2_TO_TOKIO_TRANSPORT"
    assert result["evidence"]["async_linearizability_proved"] is False
    evidence = json.loads((tmp_path / "Transport.rs.canonical.json").read_text(encoding="utf-8"))
    assert evidence["claim"] == "REVIEWED_TRANSFORMATION"


def test_repl_continues_after_argparse_error():
    class BadFlagThenQuit:
        def __init__(self, *args, **kwargs):
            self.lines = iter(["/verify X.java --bogus-flag", "/quit"])
        def prompt(self, _prompt):
            return next(self.lines)
    parser = cli.build_parser()
    store_dir = __import__("tempfile").mkdtemp()
    store = cli.SessionStore(Path(store_dir))
    with patch.object(cli, "PromptSession", BadFlagThenQuit):
        assert cli.repl(parser, _ui(), store, store.empty()) == 0


def test_canonical_draft_dispatcher_routes_all_languages_and_rejects_unknown(tmp_path):
    from pipeline.canonical_draft import canonical_draft

    domains = tmp_path / "domains" / "v2"
    domains.mkdir(parents=True)
    (domains / "counter.json").write_text("{}", encoding="utf-8")
    rust = SimpleNamespace(module_name="counter", domain_name="Counter",
                           accepted_candidate_sha256="a" * 64,
                           accepted_evidence_sha256="b" * 64,
                           execution_model="atomic", concurrency=None)
    with patch("pipeline.v2_prusti_serializer.render_reviewed_v2_prusti_file",
               return_value=(rust, "pub struct Counter {}")), \
         patch("pipeline.rust_support.lint_rust", return_value=[]), \
         patch("pipeline.rust_support.check_rust_syntax",
               return_value={"status": "RUST_CHECKED"}):
        result = canonical_draft("counter", lang="rust",
                                 out_file=tmp_path / "Counter.rs", project_root=tmp_path)
        assert result["evidence"]["transformation"] == "DETERMINISTIC_V2_TO_PRUSTI"

    c_ns = SimpleNamespace(module_name="counter", domain_name="counter",
                           accepted_candidate_sha256="a" * 64,
                           accepted_evidence_sha256="b" * 64)
    with patch("pipeline.v2_acsl_serializer.render_reviewed_v2_acsl_file",
               return_value=(c_ns, "typedef struct { int c; } counter;")), \
         patch("pipeline.c_support.lint_acsl", return_value=[]), \
         patch("pipeline.c_support.check_c_syntax", return_value={"status": "C_CHECKED"}):
        result = canonical_draft("counter", lang="c",
                                 out_file=tmp_path / "counter.c", project_root=tmp_path)
        assert result["evidence"]["transformation"] == "DETERMINISTIC_V2_TO_ACSL"

    cpp_ns = SimpleNamespace(module_name="counter", domain_name="Counter",
                             accepted_candidate_sha256="a" * 64,
                             accepted_evidence_sha256="b" * 64)
    with patch("pipeline.v2_cpp_serializer.render_reviewed_v2_cpp_file",
               return_value=(cpp_ns, "class Counter {};")), \
         patch("pipeline.cpp_support.check_cpp_syntax",
               return_value={"status": "CPP_CHECKED"}):
        result = canonical_draft("counter", lang="cpp",
                                 out_file=tmp_path / "Counter.cpp", project_root=tmp_path)
        assert result["evidence"]["claim"] == "BOUNDED_CPP_EVIDENCE"

    with patch("pipeline.v2_jml_serializer.render_reviewed_v2_file",
               return_value=(SimpleNamespace(module_name="counter", domain_name="Counter",
                                             accepted_candidate_sha256="a" * 64,
                                             accepted_evidence_sha256="b" * 64,
                                             concurrency=None),
                             "public class Counter {}")), \
         patch("pipeline.validate.check_stub", return_value=(True, [])):
        result = canonical_draft("counter", lang="java",
                                 out_file=tmp_path / "Counter.java", project_root=tmp_path)
        assert result["evidence"]["claim"] == "REVIEWED_TRANSFORMATION"

    try:
        canonical_draft("counter", lang="python", project_root=tmp_path)
    except ValueError as exc:
        assert "unsupported canonical draft language" in str(exc)
    else:
        raise AssertionError("unknown language must be rejected")
