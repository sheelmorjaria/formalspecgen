# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from pipeline import cli
from pipeline.domains.traffic_light_controller_render import render_traffic_light_controller
from pipeline.extract_tla_ir import UnsupportedJmlSemantics
from pipeline.scaffold_domain import DomainSpec
from pipeline.domain_v2 import DomainSpecV2


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = io.StringIO()
        self.console = Console(file=self.output, force_terminal=False, width=120)
        self.store = cli.SessionStore(self.root)
        self.state = self.store.empty()
        self.ui = cli.TerminalUI(self.console, lambda _prompt: "answer")

    def tearDown(self):
        self.temp.cleanup()

    def test_session_round_trip_clear_and_invalid_data(self):
        self.assertEqual(self.store.load(), self.store.empty())
        self.state["requirement"] = "counter"
        self.store.save(self.state)
        self.assertEqual(self.store.load()["requirement"], "counter")
        self.store.path.write_text("not json", encoding="utf-8")
        self.assertEqual(self.store.load(), self.store.empty())
        self.store.clear()
        self.store.clear()

    def test_terminal_events_render_every_supported_shape(self):
        for event in [
            {"type": "progress", "message": "checking"},
            {"type": "progress", "stage": "drafting"},
            {"type": "spec_warning", "line": 3, "message": "frame missing"},
            {"type": "vc_failure", "file": "X.java", "line": 4,
             "category": "Postcondition", "message": "failed", "explanation": "why"},
            {"type": "vc_failure", "advice": "bound it"},
            {"type": "attempt_complete", "attempt": 1, "status": "VERIFIED"},
            {"type": "attempt_complete", "attempt": 2, "status": "COMPILE_FAILED"},
            {"type": "ignored"},
        ]:
            self.ui.event(event)
        text = self.output.getvalue()
        self.assertIn("checking", text)
        self.assertIn("Postcondition", text)
        self.assertIn("VERIFIED", text)

    def test_clarification_is_checkpointed_and_resumed(self):
        questions = [{"id": "q1", "category": "bounds", "question": "Maximum?", "required": True}]
        with patch.object(cli, "extract_ambiguities", return_value=(questions, "m", {})) as elicited:
            enriched = self.ui.clarify("A counter", "ollama", None, self.state, self.store)
            self.assertIn("A: answer", enriched)
            self.ui.clarify("A counter", "ollama", None, self.state, self.store)
            elicited.assert_called_once()
        self.ui.ask = lambda _prompt: ""
        with patch.object(cli, "extract_ambiguities", return_value=(questions, "m", {})):
            with self.assertRaises(ValueError):
                self.ui.clarify("Another counter", "ollama", None, self.state, self.store)

    def test_read_and_json_output(self):
        source = self.root / "X.java"
        source.write_text("class X {}", encoding="utf-8")
        self.assertEqual(cli._read(str(source)), "class X {}")
        destination = self.root / "result.json"
        cli._write_json({"ok": True}, str(destination), self.console)
        self.assertTrue(json.loads(destination.read_text())["ok"])
        cli._write_json({"ok": True}, None, self.console)

    def test_json_output_creates_missing_parent_directories(self):
        destination = self.root / "nested" / "evidence" / "result.json"
        cli._write_json({"status": "ok"}, str(destination), self.console)
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8"))["status"], "ok")

    def test_draft_success_and_validation_failure(self):
        stub = self.root / "run" / "attempt1" / "X.java"
        stub.parent.mkdir(parents=True)
        stub.write_text("class X {}", encoding="utf-8")
        args = SimpleNamespace(requirement="counter", provider="ollama", model=None,
            no_clarify=True, fallback_provider=None, out=None, max_attempts=None,
            resample_budget=None, feedback_budget=None, lang="java", out_file=None)
        result = SimpleNamespace(stub_path=str(stub), final_status="VERIFIED")
        with patch.object(cli, "draft_contract", return_value=result):
            self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 0)
        self.assertEqual(self.state["last_stub"], str(stub))
        args.no_clarify = False
        with patch.object(self.ui, "clarify", side_effect=ValueError("missing")):
            self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 2)
        args.no_clarify = True
        with patch.object(cli, "draft_contract",
                          return_value=SimpleNamespace(stub_path="", final_status="FAILED")):
            self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 1)

    def test_canonical_domain_draft_writes_contract_and_evidence(self):
        destination = self.root / "TrafficLightController.java"
        args = SimpleNamespace(
            requirement="Design a traffic-light controller with mutually exclusive greens",
            provider="ollama", model=None, no_clarify=True, lang="java",
            canonical_domain="traffic_light_controller", out_file=str(destination),
            fallback_provider=None, out=None, max_attempts=None,
            resample_budget=None, feedback_budget=None)
        with patch("pipeline.validate.check_stub", return_value=(True, [])):
            self.assertEqual(cli.command_draft(
                args, self.ui, self.store, self.state), 0)
        self.assertIn("public void turnNsYellow()", destination.read_text())
        evidence = json.loads(destination.with_suffix(
            ".java.canonical.json").read_text())
        self.assertEqual(evidence["status"], "CANONICAL_CONTRACT")
        self.assertTrue(evidence["human_acceptance_required"])
        self.assertFalse(evidence["source_refinement_proved"])

        with patch("pipeline.validate.check_stub", return_value=(False, ["bad"])):
            self.assertEqual(cli.command_draft(
                args, self.ui, self.store, self.state), 2)

    def test_reviewed_v2_canonical_domain_deterministically_writes_jml(self):
        reviewed_dir = self.root / "domains/v2"
        reviewed_dir.mkdir(parents=True)
        reviewed = {
            "schema_version": 2, "review_status": "reviewed",
            "domain_name": "SmartLock", "module_name": "smart_lock", "actors": 1,
            "state_variables": [
                {"kind": "int", "name": "door_state", "bound": [0, 1], "initial": 1}],
            "operations": [{"name": "OpenDoor", "return_type": "void",
                "failure_semantics": "unavailable", "guards": [],
                "effects": [{"id": "open", "target": "door_state",
                             "value": {"kind": "integer", "value": 0}}],
                "frame": ["door_state"]}],
            "tlc_invariants": [{"id": "DoorTyped", "expression": {
                "kind": "gte", "left": {"kind": "field", "name": "door_state"},
                "right": {"kind": "integer", "value": 0}}}],
            "accepted_candidate_sha256": "a" * 64,
            "accepted_evidence_sha256": "b" * 64,
        }
        (reviewed_dir / "smart_lock.json").write_text(json.dumps(reviewed))
        destination = self.root / "SmartLock.java"
        args = SimpleNamespace(requirement="A smart lock", provider="ollama", model=None,
            no_clarify=True, lang="java", canonical_domain="smart_lock",
            out_file=str(destination), fallback_provider=None, out=None,
            max_attempts=None, resample_budget=None, feedback_budget=None)
        with patch("pipeline.validate.check_stub", return_value=(True, [])):
            self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 0)
        self.assertIn("public class SmartLock", destination.read_text())
        self.assertIn("private /*@ spec_public @*/ int door_state;", destination.read_text())
        evidence = json.loads(destination.with_suffix(".java.canonical.json").read_text())
        self.assertEqual(evidence["transformation"], "DETERMINISTIC_V2_TO_JML")
        self.assertEqual(evidence["accepted_candidate_sha256"], "a" * 64)
        args.out_file = str(self.root / "WrongName.java")
        with patch("pipeline.validate.check_stub", return_value=(True, [])):
            self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 2)
        self.assertFalse(Path(args.out_file).exists())

    def test_implement_success_and_failure(self):
        stub = self.root / "X.java"; stub.write_text("class X {}", encoding="utf-8")
        args = SimpleNamespace(stub=str(stub), provider="ollama", model=None, out=None,
            max_attempts=2, resample_budget=1, feedback_budget=1, accept_pass=[], json=None)
        args.assurance_level = "critical"; args.clarifications = ""; args.abstraction = "atomic_operations"
        args.method_proof_only = False
        with patch.object(cli, "run_implementation_loop",
                          return_value={"final_status": "VERIFIED"}):
            self.assertEqual(cli.command_implement(args, self.ui), 0)
        with patch.object(cli, "run_implementation_loop",
                          return_value={"final_status": "VERIFY_FAILED"}):
            self.assertEqual(cli.command_implement(args, self.ui), 1)
        rust = self.root / "X.rs"; rust.write_text("fn x() {}", encoding="utf-8")
        args.stub = str(rust)
        with patch.object(cli, "run_implementation_loop",
                          return_value={"final_status": "VERIFIED"}) as synthesizer:
            self.assertEqual(cli.command_implement(args, self.ui), 0)
            synthesizer.assert_called_once()
        cfile = self.root / "X.c"; cfile.write_text("int x(void) { return 0; }", encoding="utf-8")
        args.stub = str(cfile); args.accept_pass = ["inject_null_checks"]
        with patch.object(cli, "run_implementation_loop",
                          return_value={"final_status": "VERIFIED"}) as synthesizer:
            self.assertEqual(cli.command_implement(args, self.ui), 0)
            self.assertEqual(synthesizer.call_args.kwargs["accepted_passes"],
                             ["inject_null_checks"])
        args.stub = str(self.root / "X.txt"); args.accept_pass = []
        self.assertEqual(cli.command_implement(args, self.ui), 2)
        args.stub = str(stub)
        with patch.object(cli, "run_implementation_loop", side_effect=ValueError("bad route")):
            self.assertEqual(cli.command_implement(args, self.ui), 2)

    def test_verify_success_failure_and_json(self):
        args = SimpleNamespace(source="X.java", mode="esc", json=str(self.root / "v.json"),
                               backend="prusti")
        with patch.object(cli, "verify", return_value=(0, "ok")):
            self.assertEqual(cli.command_verify(args, self.ui), 0)
        with patch.object(cli, "verify", return_value=(6, "bad")):
            self.assertEqual(cli.command_verify(args, self.ui), 1)
        args.json = None
        with patch.object(cli, "verify", return_value=(0, "")):
            self.assertEqual(cli.command_verify(args, self.ui), 0)

    def test_command_verify_hal_success_failure_and_json(self):
        args = SimpleNamespace(source="hal.h",
                               json_out=str(self.root / "hal.json"))
        proved = {"status": "HAL_VERIFICATION_PROVED",
                  "claim": "HAL_REASONING_PROVED",
                  "lanes": ["register_bitfield_separation"]}
        with patch("pipeline.hal_mmio.verify_hal", return_value=proved) as hal:
            self.assertEqual(cli.command_verify_hal(args, self.ui), 0)
            hal.assert_called_once_with("hal.h")
        refused = {"status": "HAL_VERIFICATION_FAILED", "claim": "NO_PROOF",
                   "code": "UNSUPPORTED_BOUNDARY", "message": "raw RMW"}
        args.json_out = None
        with patch("pipeline.hal_mmio.verify_hal", return_value=refused):
            self.assertEqual(cli.command_verify_hal(args, self.ui), 1)

    def test_dispatch_routes_new_lanes(self):
        """main() dispatches the new subcommands (in-process so coverage
        sees the dispatch lines)."""
        macro = self.root / "macros.json"
        macro.write_text('{"READ_ONCE": "V2::Read"}', encoding="utf-8")
        src = self.root / "s.c"
        src.write_text("struct dev { int state; };\n"
                       "void f(struct dev *d) {"
                       " if (READ_ONCE(d->state) == 1) {} }\n",
                       encoding="utf-8")
        dispatches = [
            ["verify-hal", str(src)],
            ["macro-dictionary", str(macro), "--source", str(src)],
            ["verify-lockfree", str(src)],
            ["verify-linearizability", str(src)],
        ]
        for argv in dispatches:
            try:
                self.assertIn(cli.main(argv), (0, 1, 2))
            except SystemExit as exit_code:
                self.assertIn(exit_code.code, (None, 0, 1, 2))

    def test_command_verify_lockfree(self):
        args = SimpleNamespace(source="ring.c", json_out=None)
        proved = {"status": "LOCK_FREE_LINEARIZABILITY_PROVED",
                  "claim": "LOCK_FREE_LINEARIZABILITY_PROVED",
                  "scope": "concurrent_interleaving_bmc"}
        with patch("pipeline.lockfree.verify_lockfree",
                   return_value=proved) as run:
            self.assertEqual(cli.command_verify_lockfree(args, self.ui), 0)
            run.assert_called_once_with("ring.c")
        refused = {"status": "LOCK_FREE_VERIFICATION_FAILED",
                   "claim": "NO_PROOF", "code": "mpmc_not_in_dialect",
                   "message": "two writers of head"}
        with patch("pipeline.lockfree.verify_lockfree",
                   return_value=refused):
            self.assertEqual(cli.command_verify_lockfree(args, self.ui), 1)

    def test_command_macro_dictionary_phases(self):
        from types import SimpleNamespace
        args = SimpleNamespace(
            dictionary="macros.json", source=None, synthesize=False,
            no_verify=False, provider=None, json_out=None)
        loaded = {"status": "MACRO_DICTIONARY_LOADED", "entries": 2,
                  "dictionary": {"READ_ONCE": "V2::Read"}}
        with patch("pipeline.macro_semantics.load_macro_dictionary",
                   return_value=loaded):
            self.assertEqual(cli.command_macro_dictionary(args, self.ui), 0)
        args.synthesize, args.source = True, "dev.c"
        synthesized = {"status": "V2_SYNTHESIZED_FROM_MACROS",
                       "claim": "MACRO_SYNTHESIS_PROVED"}
        with patch("pipeline.macro_semantics.synthesize_v2_from_macros",
                   return_value=synthesized) as run:
            self.assertEqual(cli.command_macro_dictionary(args, self.ui), 0)
            run.assert_called_once()
        failed = {"status": "MACRO_TRANSLATION_FAILED", "claim": "NO_PROOF",
                  "code": "dictionary_malformed", "message": "bad json"}
        with patch("pipeline.macro_semantics.synthesize_v2_from_macros",
                   return_value=failed):
            self.assertEqual(cli.command_macro_dictionary(args, self.ui), 1)
        args.synthesize, args.source = False, None
        with patch("pipeline.macro_semantics.load_macro_dictionary",
                   return_value=failed):
            self.assertEqual(cli.command_macro_dictionary(args, self.ui), 1)
        # --synthesize without --source refuses with usage guidance
        args.synthesize, args.source = True, None
        self.assertEqual(cli.command_macro_dictionary(args, self.ui), 2)
        # --json writes the verdict artifact
        args.synthesize, args.source, args.json_out = False, None, str(
            self.root / "dict.json")
        with patch("pipeline.macro_semantics.load_macro_dictionary",
                   return_value=loaded):
            self.assertEqual(cli.command_macro_dictionary(args, self.ui), 0)
        import json as json_module
        written = json_module.loads(
            (self.root / "dict.json").read_text(encoding="utf-8"))
        self.assertEqual(written["status"], "MACRO_DICTIONARY_LOADED")
        args.json_out = None

    def test_macro_dictionary_cli_end_to_end(self):
        import json as json_module
        import subprocess, sys
        macro_path = self.root / "macros.json"
        macro_path.write_text(
            json_module.dumps({"READ_ONCE": "V2::Read"}), encoding="utf-8")
        # dictionary-only load through the real parser and dispatch
        completed = subprocess.run(
            [sys.executable, "-m", "pipeline.cli", "macro-dictionary",
             str(macro_path)], capture_output=True, text=True, timeout=120)
        self.assertIn("MACRO_DICTIONARY_LOADED", completed.stdout)
        self.assertEqual(completed.returncode, 0)
        # the translate branch (--source, no --synthesize)
        source = self.root / "dev.c"
        source.write_text(
            "struct dev { int state; };\n"
            "void f(struct dev *d) { if (READ_ONCE(d->state) == 1) {} }\n",
            encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, "-m", "pipeline.cli", "macro-dictionary",
             str(macro_path), "--source", str(source)],
            capture_output=True, text=True, timeout=120)
        self.assertIn("MACROS_TRANSLATED", completed.stdout)
        self.assertEqual(completed.returncode, 0)
        self.assertNotIn("--synthesize requires", completed.stdout)

    def test_polyglot_draft_and_verify_routes(self):
        args = SimpleNamespace(requirement="counter", provider="ollama", model=None,
            no_clarify=True, fallback_provider=None, out=None, max_attempts=None,
            resample_budget=None, feedback_budget=None, lang="rust",
            out_file=str(self.root / "Counter.rs"))
        with patch.object(cli, "draft_rust", return_value={
                "status": "RUST_CHECKED", "code": "fn counter() {}", "warnings": []}):
            self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 0)
        args.lang = "c"; args.out_file = str(self.root / "counter.c")
        with patch.object(cli, "draft_acsl", return_value={
                "status": "DRAFTED", "code": "int counter(void) { return 0; }", "warnings": []}):
            self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 0)

        rust = self.root / "Counter.rs"; rust.write_text("fn counter() {}", encoding="utf-8")
        verify_args = SimpleNamespace(source=str(rust), mode="esc", backend="prusti", json=None)
        with patch.object(cli, "verify_rust", return_value={"status": "VERIFIED", "exit_code": 0}):
            self.assertEqual(cli.command_verify(verify_args, self.ui), 0)
        verify_args.backend = "kani"
        with patch.object(cli, "verify_rust", return_value={"status": "VERIFY_FAILED", "exit_code": 1}):
            self.assertEqual(cli.command_verify(verify_args, self.ui), 1)
        verify_args.backend = "prusti"; verify_args.mode = "check"
        with patch.object(cli, "verify_rust", return_value={"status": "RUST_CHECKED", "exit_code": 0}):
            self.assertEqual(cli.command_verify(verify_args, self.ui), 0)

        cfile = self.root / "counter.c"; cfile.write_text("int counter(void) { return 0; }", encoding="utf-8")
        verify_args.source = str(cfile); verify_args.mode = "esc"
        with patch.object(cli, "verify_c", return_value={"status": "VERIFIED", "exit_code": 0}):
            self.assertEqual(cli.command_verify(verify_args, self.ui), 0)
        verify_args.mode = "check"
        self.assertEqual(cli.command_verify(verify_args, self.ui), 1)
        cpp = self.root / "counter.cpp"; cpp.write_text("int main() {}", encoding="utf-8")
        verify_args.source = str(cpp); verify_args.mode = "esc"
        with patch("pipeline.verify_cpp.verify_cpp",
                   return_value={"status": "VERIFIED", "exit_code": 0,
                                 "claim": "BOUNDED_CPP_PROOF"}):
            self.assertEqual(cli.command_verify(verify_args, self.ui), 0)
        unknown = self.root / "x.txt"; unknown.write_text("x", encoding="utf-8")
        verify_args.source = str(unknown); verify_args.mode = "esc"
        self.assertEqual(cli.command_verify(verify_args, self.ui), 1)

    def test_rust_lint_blocks_verification_and_failed_language_draft(self):
        source = self.root / "Unsafe.rs"; source.write_text("unsafe fn x() {}", encoding="utf-8")
        args = SimpleNamespace(source=str(source), mode="esc", backend="prusti", json=None)
        with patch.object(cli, "verify_rust", return_value={
                "status": "RUST_LINT_FAILED", "exit_code": 2}):
            self.assertEqual(cli.command_verify(args, self.ui), 1)
        draft_args = SimpleNamespace(out_file=None)
        self.assertEqual(cli._finish_language_draft(
            {"status": "PARSE_ERROR", "warnings": [{"line": 1, "message": "bad"}]},
            draft_args, self.ui, self.store, self.state, "rs"), 1)

    def test_cpp_canonical_draft_writes_bounded_evidence(self):
        reviewed_path = self.root / "domains" / "v2" / "counter.json"
        reviewed_path.parent.mkdir(parents=True)
        reviewed_path.write_text("{}", encoding="utf-8")
        destination = self.root / "Counter.cpp"
        args = SimpleNamespace(canonical_domain="counter", out_file=str(destination))
        reviewed = SimpleNamespace(module_name="counter", accepted_candidate_sha256="a" * 64,
                                   accepted_evidence_sha256="b" * 64)
        with patch("pipeline.v2_cpp_serializer.render_reviewed_v2_cpp_file",
                   return_value=(reviewed, "class Counter {};")), \
             patch("pipeline.cpp_support.check_cpp_syntax",
                   return_value={"status": "CPP_CHECKED"}):
            from pipeline.canonical_draft import canonical_draft_cpp
            result = canonical_draft_cpp("counter", "counter",
                                         domains_root=self.root / "domains" / "v2",
                                         out_file=args.out_file)
            assert result["evidence"]["claim"] == "BOUNDED_CPP_EVIDENCE"
        assert destination.read_text() == "class Counter {};"
        evidence = json.loads(destination.with_suffix(".cpp.canonical.json").read_text())
        assert evidence["claim"] == "BOUNDED_CPP_EVIDENCE"

    def test_cpp_draft_requires_canonical_domain(self):
        args = SimpleNamespace(lang="cpp", canonical_domain=None, requirement="counter",
                               provider="ollama", model=None, no_clarify=True)
        self.assertEqual(cli.command_draft(args, self.ui, self.store, self.state), 2)

    def test_implement_dependencies_routes_external_adapter_only(self):
        adapter = self.root / "StripePaymentGateway.java"
        adapter.write_text("// UNVERIFIED EXTERNAL BOUNDARY", encoding="utf-8")
        args = SimpleNamespace(stub=str(adapter), dependencies="stripe", provider="ollama",
                               model=None, json=None)
        with patch("pipeline.dependency_injection.inject_dependency",
                   return_value={"status": "INJECTED", "claim": "UNVERIFIED_EXTERNAL_ADAPTER"}):
            self.assertEqual(cli.command_implement(args, self.ui), 0)
        args.stub = str(self.root / "thing.rs")
        self.assertEqual(cli.command_implement(args, self.ui), 2)

    def test_cpp_canonical_draft_rejects_invalid_domain_and_missing_tool(self):
        args = SimpleNamespace(canonical_domain="bad-name", out_file=None)
        from pipeline.canonical_draft import canonical_draft_cpp
        domains_root = self.root / "domains" / "v2"
        with self.assertRaisesRegex(ValueError, "safe module"):
            canonical_draft_cpp("bad-name", "counter", domains_root=domains_root)
        with self.assertRaisesRegex(ValueError, "reviewed V2 domain"):
            canonical_draft_cpp("missing", "counter", domains_root=domains_root)
        domain = self.root / "domains" / "v2" / "counter.json"
        domain.parent.mkdir(parents=True); domain.write_text("{}", encoding="utf-8")
        args.canonical_domain = "counter"
        reviewed = SimpleNamespace(module_name="counter")
        with patch("pipeline.v2_cpp_serializer.render_reviewed_v2_cpp_file",
                   return_value=(reviewed, "bad")), \
             patch("pipeline.cpp_support.check_cpp_syntax",
                   return_value={"status": "CPP_CHECK_FAILED", "output": "syntax"}):
            with self.assertRaisesRegex(ValueError, "syntax gate"):
                canonical_draft_cpp("counter", "counter", domains_root=self.root / "domains" / "v2")

    def test_architecture_success_failure_and_artifacts(self):
        stub = self.root / "X.java"; stub.write_text("class X {}", encoding="utf-8")
        emitted = self.root / "Model.tla"
        args = SimpleNamespace(stub=str(stub), clarifications="atomic", abstraction="atomic_operations",
                               emit_tla=str(emitted), json=str(self.root / "a.json"))
        result = {"status": "VERIFIED", "claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
                  "domain": "x", "tla": "---- MODULE X ----\n====", "cfg": "SPECIFICATION Spec"}
        with patch.object(cli, "generate_and_check", return_value=result):
            self.assertEqual(cli.command_architecture(args, self.ui), 0)
        self.assertTrue(emitted.exists())
        args.emit_tla = None; args.json = None
        with patch.object(cli, "generate_and_check", return_value={"status": "UNSUPPORTED_BOUNDARY"}):
            self.assertEqual(cli.command_architecture(args, self.ui), 1)

    def test_domain_generation_checkpoints_and_scaffolds(self):
        spec_value = {"domain_name": "Switch", "module_name": "switch",
            "state_variables": [{"name": "state", "type": "int", "bound": [0, 1]}],
            "operations": [{"name": "turnOn", "guards": [], "effect": "set_on",
                            "frame": ["state"], "ast_pattern": "state == 1"}],
            "tlc_invariants": ["TypeOK"]}
        spec = DomainSpec.model_validate(spec_value)
        question = [{"id": "q1", "category": "state", "question": "Initial?", "required": True}]
        args = SimpleNamespace(idea="switch", provider="ollama", model=None,
                               project_root=str(self.root), force=False)
        output = self.root / "pipeline/domains/switch.py"
        with patch.object(cli, "elicit_domain_questions", return_value=(question, "m", {})), \
             patch.object(cli, "compile_domain_spec", return_value=(spec, "yaml", "m", {})), \
             patch.object(cli, "scaffold_domain", return_value=[output]):
            self.assertEqual(cli.command_domain(args, self.ui, self.store, self.state), 0)
        self.assertEqual(self.state["domain_draft"], {})
        candidate = self.root / "domains/candidates/switch.generated.yaml"
        self.assertTrue(candidate.exists())
        candidate.write_text("exists", encoding="utf-8")
        self.state["domain_draft"] = {"idea": "switch", "questions": question,
                                      "answers": [{"id": "q1", "answer": "off"}]}
        with patch.object(cli, "compile_domain_spec", return_value=(spec, "yaml", "m", {})):
            self.assertEqual(cli.command_domain(args, self.ui, self.store, self.state), 2)

        canonical = self.root / "domains/switch.yaml"
        canonical.write_text(cli.yaml.safe_dump(spec.model_copy(
            update={"review_status": "reviewed"}).model_dump(mode="json")), encoding="utf-8")
        args.force = True
        args.restart_clarifications = False
        self.state["domain_draft"] = {"idea": "switch", "questions": question,
                                      "answers": [{"id": "q1", "answer": "off"}]}
        with patch.object(cli, "compile_domain_spec", return_value=(spec, "yaml", "m", {})):
            self.assertEqual(cli.command_domain(args, self.ui, self.store, self.state), 2)
        self.state["domain_draft"] = {}
        self.ui.ask = lambda _prompt: ""
        with patch.object(cli, "elicit_domain_questions", return_value=(question, "m", {})):
            self.assertEqual(cli.command_domain(args, self.ui, self.store, self.state), 2)

        args.restart_clarifications = True
        self.state["domain_draft"] = {"idea": "switch", "questions": question,
                                      "answers": [{"id": "q1", "answer": "stale"}]}
        with patch.object(cli, "elicit_domain_questions", return_value=(question, "m", {})), \
             patch.object(cli, "compile_domain_spec", return_value=(spec, "yaml", "m", {})), \
             patch.object(cli, "scaffold_domain", return_value=[output]):
            self.assertEqual(cli.command_domain(args, self.ui, self.store, self.state), 2)

    def test_v2_domain_generation_writes_typed_candidate_without_v1_scaffold(self):
        value = {"schema_version": 2, "review_status": "unreviewed",
            "domain_name": "Switch", "module_name": "switch", "actors": 1,
            "state_variables": [{"kind": "bool", "name": "enabled", "initial": False}],
            "operations": [{"name": "Enable", "return_type": "void",
                "failure_semantics": "unavailable", "guards": [],
                "effects": [{"id": "set", "target": "enabled",
                             "value": {"kind": "boolean", "value": True}}],
                "frame": ["enabled"]}],
            "tlc_invariants": [{"id": "Safe", "expression": {"kind": "or",
                "left": {"kind": "field", "name": "enabled"},
                "right": {"kind": "eq", "left": {"kind": "field", "name": "enabled"},
                          "right": {"kind": "boolean", "value": False}}}}]}
        spec = DomainSpecV2.model_validate(value)
        question = [{"id": "q", "category": "state", "question": "Initial?",
                     "required": True}]
        args = SimpleNamespace(idea="switch", provider="ollama", model=None,
            project_root=str(self.root), force=False, schema_version=2,
            restart_clarifications=False, replace_reviewed_domain=False)
        evidence = SimpleNamespace(candidate_sha256="a" * 64,
                                   reachable_state_count=2,
                                   reachable_transition_count=1)
        with patch.object(cli, "elicit_domain_questions", return_value=(question, "m", {})), \
             patch.object(cli, "compile_domain_spec_v2", return_value=(spec, "typed yaml", "m", {})), \
             patch.object(cli, "validate_v2_candidate", return_value=evidence) as validate, \
             patch.object(cli, "scaffold_domain") as scaffold:
            self.assertEqual(cli.command_domain(args, self.ui, self.store, self.state), 0)
        scaffold.assert_not_called()
        self.assertEqual(validate.call_args.args[0].name, "switch.v2.yaml")
        self.assertEqual(validate.call_args.args[1].name, "switch.v2.validation.json")
        self.assertEqual(validate.call_args.kwargs["failure_path"].name,
                         "switch.v2.validation_failed.json")
        self.assertEqual((self.root / "domains/candidates/switch.v2.yaml").read_text(),
                         "typed yaml")

    def test_v2_domain_generation_fails_closed_when_validation_fails(self):
        value = {"schema_version": 2, "review_status": "unreviewed",
            "domain_name": "Switch", "module_name": "switch", "actors": 1,
            "state_variables": [{"kind": "bool", "name": "enabled", "initial": False}],
            "operations": [{"name": "Enable", "return_type": "void",
                "failure_semantics": "unavailable", "guards": [],
                "effects": [{"id": "set", "target": "enabled",
                             "value": {"kind": "boolean", "value": True}}],
                "frame": ["enabled"]}],
            "tlc_invariants": [{"id": "Safe", "expression": {"kind": "or",
                "left": {"kind": "field", "name": "enabled"},
                "right": {"kind": "eq", "left": {"kind": "field", "name": "enabled"},
                          "right": {"kind": "boolean", "value": False}}}}]}
        spec = DomainSpecV2.model_validate(value)
        args = SimpleNamespace(idea="switch", provider="ollama", model=None,
            project_root=str(self.root), force=True, schema_version=2,
            restart_clarifications=False, replace_reviewed_domain=False)
        with patch.object(cli, "elicit_domain_questions", return_value=([], "m", {})), \
             patch.object(cli, "compile_domain_spec_v2", return_value=(spec, "typed yaml", "m", {})), \
             patch.object(cli, "validate_v2_candidate", side_effect=RuntimeError("TLC failed")):
            self.assertEqual(cli.command_domain(args, self.ui, self.store, self.state), 2)
        self.assertEqual(self.state["domain_draft"]["idea"], "switch")

    def test_validate_domain_cli_success_failure_and_tla_emission(self):
        evidence = SimpleNamespace(candidate_sha256="a" * 64, reachable_state_count=2,
                                   reachable_transition_count=1)
        emitted = self.root / "Switch.tla"
        args = SimpleNamespace(name="switch", project_root=str(self.root),
                               emit_tla=str(emitted))
        with patch.object(cli, "validate_v2_candidate", return_value=evidence), \
             patch.object(cli, "load_candidate", return_value=object()), \
             patch.object(cli, "render_v2_tla", return_value=("MODULE", "CONFIG")):
            self.assertEqual(cli.command_validate_domain(args, self.ui), 0)
        self.assertEqual(emitted.read_text(), "MODULE")
        self.assertEqual(emitted.with_suffix(".cfg").read_text(), "CONFIG")
        args.emit_tla = None
        with patch.object(cli, "validate_v2_candidate", side_effect=RuntimeError("failed")):
            self.assertEqual(cli.command_validate_domain(args, self.ui), 2)

    def test_validate_domain_accepts_candidate_basenames_and_explains_v1_mismatch(self):
        assert cli._domain_candidate_name("smart-lock.v2.yaml") == "smart_lock"
        assert cli._domain_candidate_name("smart_lock.generated") == "smart_lock"
        assert cli._domain_candidate_name("smart_lock.generated.yaml") == "smart_lock"
        with self.assertRaisesRegex(ValueError, "not a path"):
            cli._domain_candidate_name("../smart_lock.v2.yaml")
        with self.assertRaisesRegex(ValueError, "safe lower-case"):
            cli._domain_candidate_name("bad.name.json")
        invalid = SimpleNamespace(name="../escape", project_root=str(self.root), emit_tla=None)
        self.assertEqual(cli.command_validate_domain(invalid, self.ui), 2)
        invalid.schema_version = 2
        invalid.accept_candidate_sha256 = "a" * 64
        invalid.replace_reviewed_domain = False
        self.assertEqual(cli.command_promote_domain(invalid, self.ui), 2)

        candidate = self.root / "domains/candidates/smart_lock.generated.yaml"
        candidate.parent.mkdir(parents=True)
        candidate.write_text("schema_version: 1\n", encoding="utf-8")
        args = SimpleNamespace(name="smart_lock.generated", project_root=str(self.root),
                               emit_tla=None)
        with patch.object(cli, "validate_v2_candidate") as validate:
            self.assertEqual(cli.command_validate_domain(args, self.ui), 2)
        validate.assert_not_called()

    def test_v2_promotion_cli_requires_hash_and_publishes_separate_registry(self):
        args = SimpleNamespace(name="switch", project_root=str(self.root), schema_version=2,
            accept_candidate_sha256=None, replace_reviewed_domain=False)
        self.assertEqual(cli.command_promote_domain(args, self.ui), 2)
        args.accept_candidate_sha256 = "a" * 64
        reviewed = SimpleNamespace(accepted_candidate_sha256=args.accept_candidate_sha256)
        with patch.object(cli, "promote_validated_candidate", return_value=reviewed) as promote:
            self.assertEqual(cli.command_promote_domain(args, self.ui), 0)
        self.assertEqual(promote.call_args.args[2], self.root / "domains/v2/switch.json")
        canonical = self.root / "domains/v2/switch.json"
        canonical.parent.mkdir(parents=True); canonical.write_text("reviewed")
        with patch.object(cli, "promote_validated_candidate"):
            self.assertEqual(cli.command_promote_domain(args, self.ui), 2)

    def test_promotion_prefers_validated_v2_when_schema_is_omitted(self):
        candidate_dir = self.root / "domains/candidates"
        candidate_dir.mkdir(parents=True)
        (candidate_dir / "smart_lock.v2.validation.json").write_text("{}")
        args = SimpleNamespace(name="smart_lock", project_root=str(self.root),
            schema_version=None, accept_candidate_sha256="a" * 64,
            replace_reviewed_domain=False)
        reviewed = SimpleNamespace(accepted_candidate_sha256=args.accept_candidate_sha256)
        with patch.object(cli, "promote_validated_candidate", return_value=reviewed) as promote:
            self.assertEqual(cli.command_promote_domain(args, self.ui), 0)
        self.assertEqual(promote.call_args.args[0],
                         candidate_dir / "smart_lock.v2.yaml")
        self.assertEqual(promote.call_args.args[2],
                         self.root / "domains/v2/smart_lock.json")

    def test_promote_domain_requires_reviewed_implementation_and_locks_result(self):
        value = {"review_status": "unreviewed", "schema_version": 1,
            "domain_name": "Switch", "module_name": "switch",
            "state_variables": [{"name": "state", "type": "int", "bound": [0, 1]}],
            "operations": [{"name": "turnOn", "guards": [], "effect": "set_on",
                            "frame": ["state"], "ast_pattern": "state == 1"}],
            "tlc_invariants": ["TypeOK"]}
        candidate = self.root / "domains/candidates/switch.generated.yaml"
        candidate.parent.mkdir(parents=True)
        candidate.write_text(cli.yaml.safe_dump(value), encoding="utf-8")
        domain_dir = self.root / "pipeline/domains"
        tests_dir = self.root / "tests"
        domain_dir.mkdir(parents=True); tests_dir.mkdir()
        (domain_dir / "switch_extract.py").write_text("def extract(): return 1\n", encoding="utf-8")
        (domain_dir / "switch_render.py").write_text("def render(): return 1\n", encoding="utf-8")
        (tests_dir / "test_switch_domain.py").write_text("def test_switch(): pass\n", encoding="utf-8")
        args = SimpleNamespace(name="switch", project_root=str(self.root),
                               replace_reviewed_domain=False)
        self.assertEqual(cli.command_promote_domain(args, self.ui), 0)
        canonical = cli.load_spec(self.root / "domains/switch.yaml")
        self.assertEqual(canonical.review_status, "reviewed")
        self.assertEqual(cli.command_promote_domain(args, self.ui), 2)

        (domain_dir / "switch_extract.py").write_text("# TODO\n", encoding="utf-8")
        (self.root / "domains/switch.yaml").unlink()
        self.assertEqual(cli.command_promote_domain(args, self.ui), 2)
        (domain_dir / "switch_extract.py").unlink()
        self.assertEqual(cli.command_promote_domain(args, self.ui), 2)
        mismatched = {**value, "domain_name": "Other", "module_name": "other"}
        candidate.write_text(cli.yaml.safe_dump(mismatched), encoding="utf-8")
        self.assertEqual(cli.command_promote_domain(args, self.ui), 2)

    def test_parser_dispatch_and_main(self):
        parser = cli.build_parser()
        args = parser.parse_args(["verify", "X.java", "--mode", "check"])
        with patch.object(cli, "command_verify", return_value=0) as called:
            self.assertEqual(cli.dispatch(args, self.ui, self.store, self.state), 0)
            called.assert_called_once()
        commands = {
            "draft": "command_draft", "implement": "command_implement",
            "architecture": "command_architecture", "domain": "command_domain",
            "validate-domain": "command_validate_domain",
            "promote-domain": "command_promote_domain",
        }
        for command, target in commands.items():
            with patch.object(cli, target, return_value=0) as called:
                self.assertEqual(cli.dispatch(SimpleNamespace(command=command), self.ui,
                                              self.store, self.state), 0)
                called.assert_called_once()
        self.assertEqual(cli.dispatch(SimpleNamespace(command="unknown"), self.ui,
                                      self.store, self.state), 2)
        with patch.object(cli, "command_verify", return_value=0), \
             patch.object(cli, "TerminalUI", return_value=self.ui), \
             patch("pathlib.Path.cwd", return_value=self.root):
            self.assertEqual(cli.main(["verify", "X.java"]), 0)

    def test_repl_command_parser_accepts_slash_plain_and_shell_forms(self):
        expected = ["implement", "X.java", "--assurance-level", "critical"]
        assert cli._repl_argv("/implement X.java --assurance-level critical") == expected
        assert cli._repl_argv("implement X.java --assurance-level critical") == expected
        assert cli._repl_argv("formalspecgen implement X.java --assurance-level critical") == expected
        assert cli._repl_argv("Design a counter") == ["draft", "Design a counter"]
        answers = iter(["X.java \\", "--mode esc"])
        assert cli._continued_line("formalspecgen verify \\", lambda _prompt: next(answers)) == \
            "formalspecgen verify X.java --mode esc"

    def test_main_console_entry_exits_and_unreviewed_renderer_fails_closed(self):
        fake_parser = SimpleNamespace(parse_args=lambda _argv: SimpleNamespace(command="unknown"))
        with patch.object(cli, "build_parser", return_value=fake_parser), \
             patch.object(cli, "TerminalUI", return_value=self.ui), \
             patch("pathlib.Path.cwd", return_value=self.root):
            with self.assertRaises(SystemExit) as stopped:
                cli.main()
        self.assertEqual(stopped.exception.code, 2)
        with self.assertRaises(UnsupportedJmlSemantics):
            render_traffic_light_controller(None)

    def test_repl_help_session_reset_command_and_exit(self):
        class FakeSession:
            def __init__(self, *args, **kwargs): self.lines = iter(["", "/help", "/session", "/reset", "/verify X.java", "/quit"])
            def prompt(self, _prompt): return next(self.lines)
        parser = cli.build_parser()
        with patch.object(cli, "PromptSession", FakeSession), \
             patch.object(cli, "dispatch", return_value=0) as dispatched:
            self.assertEqual(cli.repl(parser, self.ui, self.store, self.state), 0)
            dispatched.assert_called_once()

        class ExitSession:
            def __init__(self, *args, **kwargs): pass
            def prompt(self, _prompt): raise EOFError
        with patch.object(cli, "PromptSession", ExitSession):
            self.assertEqual(cli.repl(parser, self.ui, self.store, self.state), 0)

        class BadThenExitSession:
            def __init__(self, *args, **kwargs): self.lines = iter(["/not-a-command", "plain requirement", "/exit"])
            def prompt(self, _prompt): return next(self.lines)
        with patch.object(cli, "PromptSession", BadThenExitSession), \
             patch.object(cli, "dispatch", return_value=0):
            self.assertEqual(cli.repl(parser, self.ui, self.store, self.state), 0)


if __name__ == "__main__":
    unittest.main()
