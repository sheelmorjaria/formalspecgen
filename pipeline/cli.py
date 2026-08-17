# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Terminal-native FormalSpecGen client over the local Python verification core."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
import yaml
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from . import __version__, config
from .c_support import draft_acsl
from .canonical_contracts import (
    CanonicalContractConflict, canonical_contract,
)
from .canonical_draft import (
    canonical_draft_c, canonical_draft_cpp, canonical_draft_java, canonical_draft_rust,
)
from .domain_generator import compile_domain_spec, compile_domain_spec_v2, elicit_domain_questions
from .domain_v2 import DomainSpecV2
from .domain_v2_promotion import candidate_sha256, load_candidate, promote_validated_candidate
from .domain_v2_tla import render_v2_tla
from .domain_v2_validation import validate_v2_candidate
from .elicit import augment_spec, extract_ambiguities
from .jml_io import class_name as java_class_name
from .llm import LLMError, _chat_fn
from .orchestrator import run as draft_contract, run_implementation_loop
from .rust_support import draft_rust
from .scaffold_domain import DomainSpec, load_spec, scaffold_domain
from .system_design import design_system, design_system_staged
from .staged_architecture import UnifiedArchitecture
from .architecture_tla_renderer import render_unified_architecture
from .architecture_tlc_gate import validate_architecture_with_tlc
from .tla_backend import generate_and_check
from .verify import classify, verify
from .verify_c import verify_c
from .verify_rust import verify_rust
from .validate import check_stub
from .v2_jml_serializer import render_reviewed_v2_file


SESSION_VERSION = 1


class SessionStore:
    """Persist non-secret interactive progress so clarification work is resumable."""

    def __init__(self, root: Path):
        self.directory = root / ".formalspecgen"
        self.path = self.directory / "session.json"
        self.history_path = self.directory / "history"

    def load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if value.get("version") == SESSION_VERSION else self.empty()
        except (OSError, ValueError, TypeError):
            return self.empty()

    @staticmethod
    def empty() -> dict[str, Any]:
        return {"version": SESSION_VERSION, "requirement": "", "questions": [],
                "answers": [], "domain_draft": {}, "last_stub": "", "last_run": ""}

    def save(self, state: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class TerminalUI:
    def __init__(self, console: Console | None = None,
                 ask: Callable[[str], str] | None = None):
        self.console = console or Console()
        self.ask = ask or input

    def event(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "progress":
            self.console.print(f"[cyan]•[/cyan] {event.get('message', event.get('stage', 'Working'))}")
        elif kind == "spec_warning":
            self.console.print(f"[yellow]⚠ line {event.get('line', 0)}:[/yellow] {event.get('message', '')}")
        elif kind == "vc_failure":
            table = Table(title="Verification condition", show_header=False)
            table.add_row("Location", f"{event.get('file', '')}:{event.get('line', 0)}")
            table.add_row("Category", str(event.get("category", "unknown")))
            table.add_row("Message", str(event.get("message", "")))
            self.console.print(table)
            explanation = event.get("explanation") or event.get("advice")
            if explanation:
                self.console.print(Panel(str(explanation), title="Explanation", border_style="yellow"))
        elif kind == "attempt_complete":
            style = "green" if event.get("status") == "VERIFIED" else "red"
            self.console.print(f"[{style}]Attempt {event.get('attempt')}: {event.get('status')}[/{style}]")

    def clarify(self, requirement: str, provider: str, model: str | None,
                state: dict[str, Any], store: SessionStore) -> str:
        if state.get("requirement") != requirement or not state.get("questions"):
            questions, _, _ = extract_ambiguities(requirement, _chat_fn(provider), model)
            state.update(requirement=requirement, questions=questions, answers=[])
            store.save(state)
        questions = state.get("questions", [])
        answers = list(state.get("answers", []))
        for index, question in enumerate(questions, 1):
            if any(item.get("id") == question["id"] for item in answers):
                continue
            self.console.print(f"[bold]{index}. {question['question']}[/bold] "
                               f"[dim]({question['category']}{', required' if question['required'] else ', optional'})[/dim]")
            answer = self.ask("Answer: ").strip()
            if question["required"] and not answer:
                raise ValueError(f"required clarification unanswered: {question['question']}")
            answers.append({"id": question["id"], "answer": answer})
            state["answers"] = answers
            store.save(state)
        return augment_spec(requirement, questions, answers)


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _write_json(value: Any, destination: str | None, console: Console) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    if destination:
        output_path = Path(destination)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text + "\n", encoding="utf-8")
        console.print(f"Evidence written to [path]{destination}[/path]")
    else:
        console.print(text)


def _finish_canonical_draft(result: dict[str, Any], title: str, ui: TerminalUI,
                            store: SessionStore, state: dict[str, Any]) -> int:
    """Persist the drafted contract in the session and announce it."""
    destination = Path(result["code_file"])
    state["last_stub"] = str(destination.resolve())
    state["last_run"] = str(destination.parent.resolve())
    store.save(state)
    ui.console.print(Panel(
        f"{title}: [path]{destination}[/path]\n"
        f"Evidence: [path]{result['evidence_file']}[/path]\nHuman review is required.",
        title="Reviewed domain contract", border_style="green"))
    return 0


def command_draft(args: argparse.Namespace, ui: TerminalUI, store: SessionStore,
                  state: dict[str, Any]) -> int:
    requirement = args.requirement
    try:
        enriched = (ui.clarify(requirement, args.provider, args.model, state, store)
                    if not args.no_clarify else requirement)
        if args.lang == "rust":
            if getattr(args, "canonical_domain", None):
                return _finish_canonical_draft(
                    canonical_draft_rust(args.canonical_domain, enriched,
                                         domains_root=store.directory.parent / "domains" / "v2",
                                         out_file=args.out_file),
                    "Canonical Rust contract", ui, store, state)
            result = draft_rust(enriched, provider=args.provider)
            return _finish_language_draft(result, args, ui, store, state, "rs")
        if args.lang == "cpp":
            if getattr(args, "canonical_domain", None):
                return _finish_canonical_draft(
                    canonical_draft_cpp(args.canonical_domain, enriched,
                                        domains_root=store.directory.parent / "domains" / "v2",
                                        out_file=args.out_file),
                    "Canonical C++ contract", ui, store, state)
            raise ValueError("C++ drafting currently requires --canonical-domain")
        if args.lang == "c":
            if getattr(args, "canonical_domain", None):
                return _finish_canonical_draft(
                    canonical_draft_c(args.canonical_domain, enriched,
                                      domains_root=store.directory.parent / "domains" / "v2",
                                      out_file=args.out_file),
                    "Canonical C contract", ui, store, state)
            result = draft_acsl(enriched, provider=args.provider)
            return _finish_language_draft(result, args, ui, store, state, "c")
        if getattr(args, "canonical_domain", None):
            return _finish_canonical_draft(
                canonical_draft_java(args.canonical_domain, enriched,
                                     domains_root=store.directory.parent / "domains" / "v2",
                                     out_file=args.out_file),
                "Canonical contract", ui, store, state)
        result = draft_contract(enriched, provider=args.provider,
            fallback_provider=args.fallback_provider, model=args.model, out_dir=args.out,
            max_attempts=args.max_attempts, on_event=ui.event,
            resample_budget=args.resample_budget, feedback_budget=args.feedback_budget)
    except (CanonicalContractConflict, LLMError, OSError, ValueError) as exc:
        ui.console.print(f"[bold red]Draft failed:[/bold red] {escape(str(exc))}")
        return 2
    if result.stub_path:
        state["last_stub"] = result.stub_path
        state["last_run"] = str(Path(result.stub_path).parent.parent)
        store.save(state)
        ui.console.print(f"Contract: [path]{result.stub_path}[/path]")
    return 0 if result.final_status == "VERIFIED" else 1


def _finish_language_draft(result: dict[str, Any], args: argparse.Namespace, ui: TerminalUI,
                           store: SessionStore, state: dict[str, Any], suffix: str) -> int:
    status = result.get("status", "UNKNOWN")
    code = result.get("code", "")
    if code:
        destination = Path(args.out_file or f"FormalSpecDraft.{suffix}")
        destination.write_text(code, encoding="utf-8")
        state["last_stub"] = str(destination.resolve())
        store.save(state)
        ui.console.print(f"Draft: [path]{destination}[/path]")
    for warning in result.get("warnings", []):
        ui.console.print(f"[yellow]⚠ line {warning.get('line', 0)}:[/yellow] {warning.get('message', '')}")
    ui.console.print(f"Status: {status}")
    return 0 if status in {"DRAFTED", "RUST_CHECKED", "VERIFIED"} else 1


def command_implement(args: argparse.Namespace, ui: TerminalUI) -> int:
    suffix = Path(args.stub).suffix.lower()
    if suffix not in {".java", ".jml", ".rs", ".c", ".cpp", ".cc", ".cxx"}:
        ui.console.print(f"[bold red]Unsupported implementation source: {suffix or '<none>'}[/bold red]")
        return 2
    dependency = getattr(args, "dependencies", None)
    if dependency:
        allowed = {".java": {"stripe"}, ".jml": {"stripe"},
                   ".rs": {"aws"}, ".cpp": {"curl"}, ".cc": {"curl"}, ".cxx": {"curl"}}
        if dependency not in allowed.get(suffix, set()):
            ui.console.print(f"[bold red]Dependency {dependency!r} cannot fill {suffix} adapters[/bold red]")
            return 2
        from .dependency_injection import inject_dependency
        result = inject_dependency(args.stub, dependency, provider=args.provider, model=args.model)
        _write_json(result, args.json, ui.console)
        return 0 if result["status"] == "INJECTED" else 1
    try:
        result = run_implementation_loop(
            args.stub, assurance_level=args.assurance_level, provider=args.provider,
            method_proof_only=args.method_proof_only,
            model=args.model, out_dir=args.out, max_attempts=args.max_attempts,
            resample_budget=args.resample_budget, feedback_budget=args.feedback_budget,
            accepted_passes=args.accept_pass, clarifications=args.clarifications or "",
            abstraction=args.abstraction,
            v2_reviewed_domain=getattr(args, "v2_reviewed_domain", None),
            v2_validation_evidence=getattr(args, "v2_validation_evidence", None),
            on_event=ui.event)
    except (OSError, ValueError) as exc:
        ui.console.print(f"[bold red]Implementation failed:[/bold red] {escape(str(exc))}")
        return 2
    parallel_wrapper = getattr(args, "parallel_wrapper", None)
    if parallel_wrapper is not None:
        if suffix != ".rs" or parallel_wrapper != "rayon":
            result = {**result, "final_status": "UNSUPPORTED_BOUNDARY", "claim": "NO_PROOF",
                      "code": "unsupported_parallel_wrapper"}
        else:
            from .parallel_wrapper import (
                check_rayon_syntax, parallel_partition_gate, render_rayon_wrapper,
            )
            kernel_code = result.get("implementation_code") or ""
            kernel_name = getattr(args, "parallel_kernel", None) or "process_chunk"
            try:
                wrapped = render_rayon_wrapper(kernel_code, kernel_name)
            except ValueError as exc:
                partition = {"status": "FAIL", "claim": "NO_PROOF",
                             "code": "unsupported_kernel_boundary", "message": str(exc)}
            else:
                wrapper_check = check_rayon_syntax(wrapped)
                partition = parallel_partition_gate(
                    kernel_code, wrapped, kernel_name,
                    kernel_deductive_proof=(result.get("final_status") == "VERIFIED" and
                                             result.get("claim") in {
                                                 "DEDUCTIVE_PROOF",
                                                 "SOURCE_MODEL_REFINEMENT"}),
                    wrapper_compiled=wrapper_check["status"] == "RAYON_CHECKED")
                partition["native_wrapper_check"] = wrapper_check
            result["parallel_partition"] = partition
            if partition["status"] == "VERIFIED":
                destination = Path(getattr(args, "parallel_out", None) or
                                   Path(args.stub).with_name(
                                       Path(args.stub).stem + "_parallel.rs"))
                destination.write_text(wrapped, encoding="utf-8")
                result.update({"final_status": "PARALLEL_PARTITION_VERIFIED",
                               "claim": "PARALLEL_PARTITION_VERIFIED",
                               "parallel_implementation_path": str(destination.resolve()),
                               "parallel_implementation_code": wrapped,
                               "partition_safety_proved": True,
                               "parallel_scheduler_proved": False})
            else:
                result.update({"final_status": "PARALLEL_PARTITION_FAILED",
                               "claim": "NO_PROOF", "partition_safety_proved": False,
                               "parallel_scheduler_proved": False})
    _write_json(result, args.json, ui.console)
    return 0 if result["final_status"] in {
        "VERIFIED", "STATIC_CHECKED", "STATIC_CHECKED_RUNTIME_TESTED", "COMPILED_LINTED",
        "LOCK_DISCIPLINE_VERIFIED", "CONCURRENT_LINEARIZABILITY_VERIFIED",
        "PARALLEL_PARTITION_VERIFIED", "ASYNC_STATIC_CHECKED"} else 1


def command_verify(args: argparse.Namespace, ui: TerminalUI) -> int:
    source = Path(args.source)
    suffix = source.suffix.lower()
    if suffix in {".java", ".jml"}:
        exit_code, output = verify(source, mode=args.mode)
        result = {"status": classify(exit_code), "exit_code": exit_code, "mode": args.mode,
                  "language": "java", "source": str(source.resolve()), "output": output}
    elif suffix == ".rs":
        result = verify_rust(_read(args.source), mode=args.mode, backend=args.backend)
    elif suffix == ".c":
        if args.mode != "esc":
            result = {"status": "UNSUPPORTED_MODE", "exit_code": 2, "claim": "NO_PROOF",
                      "language": "c", "message": "C/ACSL currently supports --mode esc through Frama-C WP"}
        else:
            result = verify_c(_read(args.source), mode=args.mode)
    elif suffix in {".cc", ".cpp", ".cxx"}:
        if args.mode != "esc":
            result = {"status": "UNSUPPORTED_MODE", "exit_code": 2, "claim": "NO_PROOF",
                      "language": "cpp", "message": "C++ supports bounded ESBMC verification through --mode esc"}
        else:
            from .verify_cpp import verify_cpp
            result = verify_cpp(source)
    else:
        result = {"status": "UNSUPPORTED_LANGUAGE", "exit_code": 2, "claim": "NO_PROOF",
                  "message": f"unsupported source extension: {suffix or '<none>'}"}
    status, exit_code = result.get("status", "UNKNOWN"), int(result.get("exit_code", 1))
    output = str(result.get("output") or result.get("message") or "")
    ui.console.print(f"[{'green' if exit_code == 0 else 'red'}]{status}[/]")
    if output.strip(): ui.console.print(Syntax(output, "text", word_wrap=True))
    if args.json:
        _write_json(result, args.json, ui.console)
    return 0 if exit_code == 0 else 1


def command_verify_refactor(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .refactor_gate import (
        verify_contract_preserving_refactor, verify_multifile_contract_refactor,
    )
    if getattr(args, "signing_key", None) and not args.json:
        ui.console.print("[bold red]Signing a refactor verdict requires --json[/bold red]")
        return 2
    ui.console.print("[cyan]Checking baseline and refactored contract surfaces…[/cyan]")
    result = (verify_multifile_contract_refactor(args.baseline, args.refactored)
              if Path(args.refactored).is_dir() else
              verify_contract_preserving_refactor(args.baseline, args.refactored))
    _write_json(result, args.json, ui.console)
    if getattr(args, "signing_key", None) and args.json:
        from .domain_v2_promotion import sign_artifact
        try:
            signature = sign_artifact(args.json, args.signing_key)
        except ValueError as exc:
            ui.console.print(f"[bold red]{escape(str(exc))}[/bold red]")
            return 2
        ui.console.print(f"[green]Refactor verdict signature:[/green] {signature}")
    return 0 if result["status"] == "VERIFIED" else 1


def command_optimize_algorithm(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .algorithm_optimization import optimize_algorithm
    result = optimize_algorithm(args.source, args.out, strategy=args.strategy,
                                provider=args.provider, model=args.model)
    if args.json:
        _write_json(result, args.json, ui.console)
    ui.console.print(f"Status: {result['status']}\nClaim: {result.get('claim', 'NO_PROOF')}")
    if result["status"] != "VERIFIED":
        ui.console.print(f"Code: {result.get('code', 'UNKNOWN')}\n"
                         f"Message: {result.get('message', 'no diagnostic available')}")
    return 0 if result["status"] == "VERIFIED" else 1


def command_discover_algorithms(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .algorithm_discovery import discover_algorithms
    selected = None if args.strategies == "all" else [item.strip() for item in args.strategies.split(",")]
    result = discover_algorithms(args.source, args.out_dir, strategies=selected,
                                 provider=args.provider, model=args.model,
                                 max_workers=args.max_workers)
    destination = args.json or str(Path(args.out_dir) / "discovery_verdict.json")
    _write_json(result, destination, ui.console)
    ui.console.print(f"Status: {result['status']}\nClaim: {result.get('claim', 'NO_PROOF')}\n"
                     f"Verified candidates: {len(result.get('verified_candidates', []))}")
    return 0 if result["status"] == "VERIFIED" else 1


def command_assess_security(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .security_assessment import assess_security
    result = assess_security(args.source, run_sast=not args.no_sast)
    _write_json(result, args.json or "security_verdict.json", ui.console)
    ui.console.print(f"Status: {result['status']}\nClaim: {result.get('claim', 'NO_PROOF')}")
    return 0 if result["status"] == "VERIFIED_SECURE" else 1


def command_security_inspect(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .security_poc import inspect_security
    result = inspect_security(args.source)
    _write_json(result, args.json or "vulnerability_report.json", ui.console)
    ui.console.print(f"Status: {result['status']}\nFindings: {len(result.get('findings', []))}")
    return 0


def command_security_exploit(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .security_poc import generate_pocs
    result = generate_pocs(args.report, args.target, args.out_dir)
    _write_json(result, args.json or str(Path(args.out_dir) / "poc-verdict.json"), ui.console)
    ui.console.print(f"Status: {result['status']}\nGenerated PoCs: {len(result.get('generated', []))}")
    return 0 if result["status"] == "POCS_GENERATED" else 1


def command_remediate(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .remediation import remediate
    result = remediate(args.target, args.report, args.out_dir,
                       provider=args.provider, model=args.model)
    _write_json(result, args.json or str(Path(args.out_dir) / "remediation_verdict.json"), ui.console)
    ui.console.print(f"Status: {result['status']}\nClaim: {result.get('claim', 'NO_PROOF')}")
    return 0 if result["status"] == "REMEDIATION_VERIFIED" else 1


def command_correct_behavior(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .behavior_correction import correct_behavior
    result = correct_behavior(args.target, args.cwe, args.out_dir,
                              provider=args.provider, model=args.model,
                              max_attempts=args.max_attempts,
                              strategy=getattr(args, "strategy", None),
                              hardware=getattr(args, "hardware", None),
                              struct_size_bytes=getattr(args, "struct_size_bytes", None))
    _write_json(result, args.json or str(Path(args.out_dir) / "correction_verdict.json"), ui.console)
    ui.console.print(f"Status: {result['status']}\nClaim: {result.get('claim', 'NO_PROOF')}")
    return 0 if result["status"] in {"BEHAVIOR_CORRECTION_VERIFIED",
                                      "CAPACITY_BOUND_CANDIDATE_GENERATED"} else 1


def command_verify_bisimulation(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .bisimulation import verify_bisimulation_inputs
    result = verify_bisimulation_inputs(args.baseline, args.refactored, args.mapping)
    _write_json(result, args.json, ui.console)
    ui.console.print(f"[{'green' if result['status'] == 'BISIMULATION_PREFLIGHT_READY' else 'red'}]"
                     f"{result['status']}[/]")
    return 0 if result["status"] == "BISIMULATION_PREFLIGHT_READY" else 1


def command_inspect(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .java_inspection import inspect_java_file
    result = inspect_java_file(args.source)
    _write_json(result, args.json, ui.console)
    return 0 if result["status"] == "INSPECTED" else 1


def command_apply_refactor(args: argparse.Namespace, ui: TerminalUI) -> int:
    suffix = Path(args.source).suffix.lower()
    if suffix in {".rs", ".c", ".cpp", ".cc", ".cxx"}:
        if args.pattern != "extract-method":
            ui.console.print("[bold red]Polyglot refactoring currently supports "
                             "extract-method only[/bold red]")
            return 2
        from .polyglot_extract_method import apply_extract_method_polyglot
        result = apply_extract_method_polyglot(args.source, args.method, args.out)
        _write_json(result, args.json, ui.console)
        return 0 if result.get("status") == "VERIFIED" else 1
    if not getattr(args, "inspection", None):
        ui.console.print("[bold red]Java refactoring requires hash-bound "
                         "--inspection evidence[/bold red]")
        return 2
    from .refactor_actions import apply_refactor
    result = apply_refactor(args.source, args.inspection, args.pattern,
                            args.method, args.out)
    _write_json(result, args.json, ui.console)
    return 0 if result.get("status") == "VERIFIED" else 1


def command_architecture(args: argparse.Namespace, ui: TerminalUI) -> int:
    result = generate_and_check(_read(args.stub), clarifications=args.clarifications or "",
                                abstraction=args.abstraction)
    status = result.get("status", "UNKNOWN")
    message = str(result.get("message") or "")
    ui.console.print(Panel(
        f"Status: {status}\nClaim: {result.get('claim', 'NO_PROOF')}\n"
        f"Domain: {result.get('domain', 'none')}\n"
        "Bounded TLC evidence does not prove Java/JML source refinement."
        + (f"\n\nReason: {message}" if message else ""),
        title="Architecture evidence", border_style="green" if status == "VERIFIED" else "red"))
    if args.emit_tla and result.get("tla"):
        Path(args.emit_tla).write_text(result["tla"], encoding="utf-8")
        Path(args.emit_tla).with_suffix(".cfg").write_text(result["cfg"], encoding="utf-8")
    if args.json:
        _write_json(result, args.json, ui.console)
    return 0 if status == "VERIFIED" else 1


def command_design_system(args: argparse.Namespace, ui: TerminalUI) -> int:
    """Generate a bounded architecture artifact from natural language."""
    ui.console.print(f"[bold cyan]Designing architecture via {args.provider}…[/bold cyan]")
    try:
        generator = design_system_staged if args.staged else design_system
        repair_feedback = ""
        result = None
        rounds = 2 if args.staged else 1
        for _ in range(rounds):
            result = generator(args.requirement, provider=args.provider,
                               max_attempts=args.max_attempts, timeout=args.timeout,
                               target_lang=getattr(args, "lang", "java"),
                               repair_feedback=repair_feedback) if args.staged else generator(
                                   args.requirement, provider=args.provider,
                                   max_attempts=args.max_attempts, timeout=args.timeout)
            if result.get("status") == "VERIFIED":
                break
            tlc = result.get("tlc", {})
            repair_feedback = str(tlc.get("output", result.get("message", "")))[:12000]
    except Exception as exc:  # fail closed at the CLI boundary
        ui.console.print(f"[bold red]Architecture generation failed:[/bold red] {escape(str(exc))}")
        return 1
    if result.get("status") != "VERIFIED" or not result.get("architecture"):
        if args.json:
            _write_json(result, args.json, ui.console)
        ui.console.print(
            f"[bold red]Architecture generation failed:[/bold red] "
            f"{escape(str(result.get('message', result.get('status', 'UNKNOWN'))))}")
        return 1
    destination = Path(args.out_file)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result["architecture"], indent=2) + "\n",
                            encoding="utf-8")
    evidence = {key: value for key, value in result.items() if key != "architecture"}
    if args.json:
        _write_json({"status": "VERIFIED", "architecture": result["architecture"],
                     "evidence": evidence}, args.json, ui.console)
    ui.console.print(f"[green]Architecture artifact written to {destination}[/green]")
    return 0


def command_validate_architecture(args: argparse.Namespace, ui: TerminalUI) -> int:
    """Validate a unified staged architecture JSON through TLA+/TLC."""
    try:
        architecture = UnifiedArchitecture.model_validate(
            json.loads(Path(args.artifact).read_text(encoding="utf-8")))
        tla, cfg = render_unified_architecture(architecture)
        import tempfile
        with tempfile.TemporaryDirectory(prefix="formalspecgen-architecture-") as directory:
            root = Path(directory)
            tla_path, cfg_path = root / f"{architecture.name}.tla", root / f"{architecture.name}.cfg"
            tla_path.write_text(tla, encoding="utf-8")
            cfg_path.write_text(cfg, encoding="utf-8")
            result = validate_architecture_with_tlc(
                tla_path, cfg_path, config.TLC_JAR, config.JAVA_BIN, args.timeout)
        if result["status"] != "VERIFIED":
            if args.json:
                _write_json({"status": result["status"], "tlc": result}, args.json, ui.console)
            ui.console.print(f"[red]Architecture validation failed: {result['status']}[/red]")
            return 1
        evidence = {"status": "VERIFIED", "claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
                    "tlc": result}
        if args.json:
            _write_json({"architecture": architecture.model_dump(), **evidence}, args.json, ui.console)
        ui.console.print("[green]Unified architecture TLC validation passed[/green]")
        return 0
    except Exception as exc:
        ui.console.print(f"[red]Architecture validation failed: {escape(str(exc))}[/red]")
        return 1


def command_analyze_codebase(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .codebase_analysis import analyze_codebase
    result = analyze_codebase(args.target_dir, args.out_dir, args.project_root)
    if args.json:
        _write_json(result, args.json, ui.console)
    ui.console.print(f"Status: {result['status']}\nComponents: {len(result.get('components', []))}")
    return 0 if result["status"] == "EXTRACTED" else 1


def command_document_code(args: argparse.Namespace, ui: TerminalUI) -> int:
    from .code_documentation import document_code
    result = document_code(args.source, args.out, project_root=args.project_root,
                           provider=args.provider, model=args.model, no_llm=args.no_llm)
    if args.json:
        _write_json(result, args.json, ui.console)
    ui.console.print(f"Status: {result['status']}")
    if result.get("document"):
        ui.console.print(f"Document: {result['document']}")
    return 0 if result["status"] == "DOCUMENTED" else 1


def command_domain(args: argparse.Namespace, ui: TerminalUI, store: SessionStore,
                   state: dict[str, Any]) -> int:
    draft = state.get("domain_draft") or {}
    idea = args.idea
    schema_version = int(getattr(args, "schema_version", 1))
    validation_evidence = None
    validation_path = None
    try:
        if getattr(args, "restart_clarifications", False):
            draft = {}
            state["domain_draft"] = {}
            store.save(state)
        if (draft.get("idea") != idea or not draft.get("questions") or
                int(draft.get("schema_version", 1)) != schema_version):
            questions, _, _ = elicit_domain_questions(idea, _chat_fn(args.provider), args.model)
            draft = {"idea": idea, "schema_version": schema_version,
                     "questions": questions, "answers": []}
            state["domain_draft"] = draft
            store.save(state)
        answers = draft["answers"]
        for index, question in enumerate(draft["questions"], 1):
            if any(item.get("id") == question["id"] for item in answers):
                continue
            ui.console.print(f"[bold]{index}. {question['question']}[/bold]")
            answer = ui.ask("Answer: ").strip()
            if question["required"] and not answer:
                raise ValueError(f"required clarification unanswered: {question['question']}")
            answers.append({"id": question["id"], "answer": answer})
            store.save(state)
        compiler = compile_domain_spec_v2 if schema_version == 2 else compile_domain_spec
        compiler_chat = _chat_fn(
            args.provider,
            json_schema=DomainSpecV2.model_json_schema() if schema_version == 2 else None)
        compiler_kwargs = ({"progress": lambda message: ui.console.print(
            f"[bold cyan]{escape(message)}[/bold cyan]")}
            if schema_version == 2 else {})
        spec, yaml_text, _, _ = compiler(
            idea, draft["questions"], answers, compiler_chat, args.model,
            **compiler_kwargs)
        root = Path(args.project_root).resolve()
        canonical = (root / "domains" / "v2" / f"{spec.module_name}.json"
                     if schema_version == 2 else root / "domains" / f"{spec.module_name}.yaml")
        canonical_reviewed = canonical.exists() and (
            schema_version == 2 or load_spec(canonical).review_status == "reviewed")
        if canonical_reviewed and not getattr(args, "replace_reviewed_domain", False):
            raise PermissionError(
                f"{spec.module_name!r} is reviewed and locked; generation cannot replace its "
                "YAML or implementation. Use --replace-reviewed-domain only after explicit review")
        suffix = ".v2.yaml" if schema_version == 2 else ".generated.yaml"
        candidate = root / "domains" / "candidates" / f"{spec.module_name}{suffix}"
        candidate.parent.mkdir(parents=True, exist_ok=True)
        if candidate.exists() and not args.force:
            raise FileExistsError(f"refusing to overwrite candidate {candidate}; pass --force")
        candidate.write_text(yaml_text, encoding="utf-8")
        outputs = ([] if schema_version == 2 else scaffold_domain(
            candidate, project_root=root, force=args.force,
            replace_reviewed=getattr(args, "replace_reviewed_domain", False)))
        if schema_version == 2:
            ui.console.print("[bold magenta]Running deterministic schema and TLC validation…[/bold magenta]")
            validation_path = candidate.with_name(
                f"{spec.module_name}.v2.validation.json")
            failure_path = candidate.with_name(
                f"{spec.module_name}.v2.validation_failed.json")
            validation_evidence = validate_v2_candidate(
                candidate, validation_path, failure_path=failure_path,
                tlc_jar=config.TLC_JAR, java=getattr(config, "JAVA_BIN", "java"),
                timeout=config.TLC_TIMEOUT)
    except (LLMError, ValueError, RuntimeError, OSError) as exc:
        ui.console.print(f"[bold red]Domain generation failed:[/bold red] {escape(str(exc))}")
        return 2
    state["domain_draft"] = {}
    store.save(state)
    ui.console.print(
        f"[green]Generated unreviewed V{schema_version} candidate {spec.module_name}[/green]")
    ui.console.print(f"  [path]{candidate}[/path]")
    for output in outputs:
        ui.console.print(f"  [path]{output}[/path]")
    if schema_version == 1:
        ui.console.print("[yellow]Human review is required for extractor and renderer TODOs.[/yellow]")
    else:
        ui.console.print(Panel(
            f"Status: VALIDATED\n"
            f"Candidate SHA-256: {validation_evidence.candidate_sha256}\n"
            f"Reachable states: {validation_evidence.reachable_state_count}\n"
            f"Reachable transitions: {validation_evidence.reachable_transition_count}\n"
            f"Evidence: {validation_path}",
            title="V2 bounded evidence", border_style="green"))
        ui.console.print(
            "[yellow]Human review and explicit hash-bound promotion are still required.[/yellow]")
    return 0


def command_validate_domain(args: argparse.Namespace, ui: TerminalUI) -> int:
    root = Path(args.project_root).resolve()
    try:
        name = _domain_candidate_name(args.name)
    except ValueError as exc:
        ui.console.print(f"[bold red]V2 domain validation failed:[/bold red] {escape(str(exc))}")
        return 2
    candidate = root / "domains" / "candidates" / f"{name}.v2.yaml"
    validation = root / "domains" / "candidates" / f"{name}.v2.validation.json"
    failure = root / "domains" / "candidates" / f"{name}.v2.validation_failed.json"
    try:
        if not candidate.exists():
            v1_candidate = root / "domains" / "candidates" / f"{name}.generated.yaml"
            if v1_candidate.exists():
                raise ValueError(
                    f"{v1_candidate.name} is a V1 plugin scaffold, not a typed V2 candidate. "
                    "V1 requires human review of its generated extractor and renderer. "
                    "Regenerate the domain with --schema-version 2 before using validate-domain.")
        evidence = validate_v2_candidate(
            candidate, validation, failure_path=failure, tlc_jar=config.TLC_JAR,
            java=getattr(config, "JAVA_BIN", "java"), timeout=config.TLC_TIMEOUT)
        if args.emit_tla:
            tla, cfg = render_v2_tla(load_candidate(candidate))
            destination = Path(args.emit_tla)
            destination.write_text(tla, encoding="utf-8")
            destination.with_suffix(".cfg").write_text(cfg, encoding="utf-8")
    except (ValueError, RuntimeError, OSError) as exc:
        ui.console.print(f"[bold red]V2 domain validation failed:[/bold red] {escape(str(exc))}")
        return 2
    ui.console.print(Panel(
        f"Status: VALIDATED\nCandidate SHA-256: {evidence.candidate_sha256}\n"
        f"Reachable states: {evidence.reachable_state_count}\n"
        f"Reachable transitions: {evidence.reachable_transition_count}\n"
        f"Evidence: {validation}", title="V2 bounded evidence", border_style="green"))
    return 0


def command_promote_domain(args: argparse.Namespace, ui: TerminalUI) -> int:
    """Promote a reviewed candidate without letting generated text assign its own trust."""
    root = Path(args.project_root).resolve()
    try:
        name = _domain_candidate_name(args.name)
    except ValueError as exc:
        ui.console.print(f"[bold red]Domain promotion failed:[/bold red] {escape(str(exc))}")
        return 2
    requested_schema = getattr(args, "schema_version", None)
    if requested_schema is None:
        v2_validation = root / "domains" / "candidates" / f"{name}.v2.validation.json"
        requested_schema = 2 if v2_validation.exists() else 1
    if int(requested_schema) == 2:
        candidate = root / "domains" / "candidates" / f"{name}.v2.yaml"
        validation = root / "domains" / "candidates" / f"{name}.v2.validation.json"
        canonical = root / "domains" / "v2" / f"{name}.json"
        try:
            if not args.accept_candidate_sha256:
                raise ValueError("V2 promotion requires --accept-candidate-sha256")
            if canonical.exists() and not args.replace_reviewed_domain:
                raise PermissionError(
                    f"reviewed V2 domain {name!r} already exists; use --replace-reviewed-domain")
            reviewed = promote_validated_candidate(
                candidate, validation, canonical,
                accept_candidate_sha256=args.accept_candidate_sha256,
                signing_key=getattr(args, "signing_key", None))
        except (ValueError, OSError) as exc:
            ui.console.print(f"[bold red]V2 domain promotion failed:[/bold red] {escape(str(exc))}")
            return 2
        ui.console.print(
            f"[green]Promoted reviewed V2 domain {name}[/green]\n"
            f"  [path]{canonical}[/path]\n"
            f"  accepted candidate: {reviewed.accepted_candidate_sha256}")
        if getattr(args, "signing_key", None):
            ui.console.print(f"  promotion signature: {canonical}.promotion.sig")
        return 0
    candidate = root / "domains" / "candidates" / f"{name}.generated.yaml"
    canonical = root / "domains" / f"{name}.yaml"
    try:
        spec = load_spec(candidate)
        if spec.module_name != name:
            raise ValueError(f"candidate declares module {spec.module_name!r}, expected {name!r}")
        if canonical.exists() and load_spec(canonical).review_status == "reviewed" and not (
                args.replace_reviewed_domain):
            raise PermissionError(
                f"reviewed domain {name!r} already exists; use --replace-reviewed-domain")
        required = [
            root / "pipeline" / "domains" / f"{name}_extract.py",
            root / "pipeline" / "domains" / f"{name}_render.py",
            root / "tests" / f"test_{name}_domain.py",
        ]
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise FileNotFoundError("promotion artifacts are missing: " + ", ".join(missing))
        forbidden = ("TODO", "plugin is scaffolded", "del code, clarifications, abstraction",
                     "del model")
        blocked = [str(path) for path in required[:2]
                   if any(marker in path.read_text(encoding="utf-8") for marker in forbidden)]
        if blocked:
            raise ValueError("adapter/renderer remains an unreviewed fail-closed stub: " +
                             ", ".join(blocked))
        reviewed = spec.model_copy(update={"review_status": "reviewed", "schema_version": 1})
        canonical.parent.mkdir(parents=True, exist_ok=True)
        canonical.write_text(yaml.safe_dump(
            reviewed.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            encoding="utf-8")
    except (ValueError, OSError) as exc:
        ui.console.print(f"[bold red]Domain promotion failed:[/bold red] {escape(str(exc))}")
        return 2
    ui.console.print(f"[green]Promoted reviewed domain {name}[/green]\n  [path]{canonical}[/path]")
    return 0


def command_compose(args: argparse.Namespace, ui: TerminalUI) -> int:
    """Compose reviewed V2 domains into orchestrators and let OpenJML ESC judge the glue."""
    from . import composition_render
    try:
        value = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        ui.console.print(f"[bold red]Composition artifact unreadable:[/bold red] {escape(str(exc))}")
        return 2
    if getattr(args, "lang", "java") != "java":
        from .polyglot_composition import verify_polyglot_composition
        verdict = verify_polyglot_composition(
            value, args.v2_dir, language=args.lang, run_esc=not args.no_esc)
        if args.out_dir and verdict.get("files"):
            destination = Path(args.out_dir)
            destination.mkdir(parents=True, exist_ok=True)
            for name, source in verdict["files"].items():
                (destination / name).write_text(source, encoding="utf-8")
        if args.json:
            Path(args.json).write_text(
                json.dumps(verdict, indent=2, ensure_ascii=False, default=str) + "\n",
                encoding="utf-8")
        style = "green" if verdict["status"] in {"COMPOSITION_VERIFIED"} else "yellow"
        ui.console.print(Panel(
            f"Status: {verdict['status']}\nClaim: {verdict.get('claim', 'NO_PROOF')}\n"
            f"Scope: {verdict.get('scope', 'n/a')}",
            title="Polyglot composition verification", border_style=style))
        if verdict.get("disclaimer"):
            ui.console.print(verdict["disclaimer"], style="dim")
        return 0 if verdict["status"] == "COMPOSITION_VERIFIED" else 1
    verdict = composition_render.verify_composition(
        value, args.v2_dir, run_esc=not args.no_esc,
        actors=getattr(args, "actors", None).split(",") if getattr(args, "actors", None) else None)
    if args.out_dir and verdict.get("files"):
        destination = Path(args.out_dir)
        destination.mkdir(parents=True, exist_ok=True)
        for name, source in verdict["files"].items():
            (destination / name).write_text(source, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(
            json.dumps(verdict, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
    style = "green" if verdict["status"] in {
        "COMPOSITION_VERIFIED", "COMPOSITION_CHECKED"} else "yellow"
    ui.console.print(Panel(
        f"Status: {verdict['status']}\nClaim: {verdict.get('claim', 'NO_PROOF')}\n"
        f"Scope: {verdict.get('scope', 'n/a')}",
        title="Composition verification", border_style=style))
    if verdict.get("disclaimer"):
        ui.console.print(verdict["disclaimer"], style="dim")
    return 0 if verdict["status"] in {
        "COMPOSITION_VERIFIED", "COMPOSITION_CHECKED"} else 1


def command_reverify(args: argparse.Namespace, ui: TerminalUI) -> int:
    """Re-prove composition after a reviewed module contract changed."""
    from . import composition_render
    try:
        value = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        ui.console.print(f"[bold red]Composition artifact unreadable:[/bold red] {escape(str(exc))}")
        return 2
    verdict = composition_render.reverify_composition(
        value, args.changed_module, args.v2_dir)
    if args.json:
        Path(args.json).write_text(
            json.dumps(verdict, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
    style = "green" if verdict["status"] in {"REVERIFIED", "NOT_IMPACTED"} else "yellow"
    ui.console.print(Panel(
        f"Status: {verdict['status']}\nChanged module: {verdict.get('changed_module')}\n"
        f"Impacted components: {', '.join(verdict.get('impacted_components') or [])}\n"
        f"Impacted use cases: {', '.join(verdict.get('impacted_use_cases') or [])}",
        title="Composition re-verification", border_style=style))
    return 0 if verdict["status"] in {"REVERIFIED", "NOT_IMPACTED"} else 1


def command_system(args: argparse.Namespace, ui: TerminalUI) -> int:
    """Verify component implementations in isolation before composing the system."""
    from .system_orchestrator import verify_system
    try:
        value = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        ui.console.print(f"[bold red]System artifact unreadable:[/bold red] {escape(str(exc))}")
        return 2
    if getattr(args, "mode", "implement") == "refactor":
        from .system_orchestrator import refactor_system
        verdict = refactor_system(value, out_dir=args.out_dir, max_workers=args.max_workers)
    elif getattr(args, "mode", "implement") == "correct":
        from .system_orchestrator import correct_system
        verdict = correct_system(value, out_dir=args.out_dir,
                                 max_workers=args.max_workers,
                                 provider=args.provider, model=args.model,
                                 max_attempts=args.max_attempts,
                                 executable=args.executable)
    else:
        verdict = verify_system(value, out_dir=args.out_dir,
                                max_workers=args.max_workers,
                                executable=args.executable)
    if args.json:
        Path(args.json).write_text(
            json.dumps(verdict, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8")
    style = "green" if verdict["status"] in {"SYSTEM_SYNTHESIS_VERIFIED",
                                              "SYSTEM_REFACTOR_VERIFIED",
                                              "SYSTEM_CORRECTION_VERIFIED"} else "red"
    ui.console.print(Panel(
        f"Status: {verdict['status']}\nClaim: {verdict.get('claim', 'NO_PROOF')}\n"
        f"Components: {len(verdict.get('components') or [])}",
        title="System verification", border_style=style))
    return 0 if verdict["status"] in {"SYSTEM_SYNTHESIS_VERIFIED",
                                      "SYSTEM_REFACTOR_VERIFIED",
                                      "SYSTEM_CORRECTION_VERIFIED"} else 1


def command_unified_system(args: argparse.Namespace, ui: TerminalUI) -> int:
    if args.lang != "java":
        from .polyglot_composition import verify_polyglot_composition
        try:
            value = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            ui.console.print(f"[bold red]Artifact unreadable:[/bold red] {escape(str(exc))}")
            return 2
        verdict = verify_polyglot_composition(
            value, getattr(args, "v2_dir", None), language=args.lang)
        if verdict.get("files"):
            destination = Path(args.out_dir)
            destination.mkdir(parents=True, exist_ok=True)
            for name, source in verdict["files"].items():
                (destination / name).write_text(source, encoding="utf-8")
        if args.json:
            _write_json(verdict, args.json, ui.console)
        ui.console.print(f"Status: {verdict.get('status')}\nClaim: {verdict.get('claim')}")
        return 0 if verdict.get("status") in {"LOWERED", "COMPOSITION_VERIFIED"} else 1
    from .unified_system_runner import run_unified_system
    verdict = run_unified_system(args.artifact, args.evidence, args.out_dir, args.lang)
    if args.json:
        _write_json(verdict, args.json, ui.console)
    ui.console.print(f"Status: {verdict.get('status')}\nClaim: {verdict.get('claim')}")
    return 0 if verdict.get("status") in {"LOWERED", "VERIFIED"} else 1


def _domain_candidate_name(value: str) -> str:
    """Accept a module name or displayed candidate filename without allowing paths."""
    raw = value.strip().lower().replace("-", "_")
    if Path(raw).name != raw:
        raise ValueError("domain candidate must be a module name or basename, not a path")
    for suffix in (".v2.validation.json", ".v2.yaml", ".generated.yaml",
                   ".generated", ".v2", ".yaml"):
        if raw.endswith(suffix):
            raw = raw[:-len(suffix)]
            break
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", raw):
        raise ValueError("domain candidate name must be a safe lower-case identifier")
    return raw


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="formalspecgen",
        description="NL → contracts → bounded architecture evidence → verified implementation")
    parser.add_argument("--version", action="version", version=f"formalspecgen {__version__}")
    sub = parser.add_subparsers(dest="command")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--provider", choices=["glm", "openai", "ollama"], default="ollama")
    common.add_argument("--model")

    draft = sub.add_parser("draft", parents=[common], help="clarify NL and draft checked JML")
    draft.add_argument("requirement")
    draft.add_argument("--no-clarify", action="store_true")
    draft.add_argument("--lang", choices=["java", "rust", "c", "cpp"], default="java")
    draft.add_argument("--out-file", help="contract destination")
    draft.add_argument("--canonical-domain", metavar="DOMAIN",
                       help="deterministically render a reviewed domain contract after clarification")
    draft.add_argument("--fallback-provider", choices=["glm", "openai", "ollama"])
    draft.add_argument("--out")
    draft.add_argument("--max-attempts", type=int)
    draft.add_argument("--resample-budget", type=int)
    draft.add_argument("--feedback-budget", type=int)

    implement = sub.add_parser("implement", parents=[common],
                               help="synthesize bodies for trusted Java/JML, Rust/Prusti, or C/ACSL")
    implement.add_argument("stub")
    implement.add_argument("--out")
    implement.add_argument("--json")
    implement.add_argument("--max-attempts", type=int, default=5)
    implement.add_argument("--resample-budget", type=int, default=1)
    implement.add_argument("--feedback-budget", type=int, default=4)
    implement.add_argument("--accept-pass", action="append", default=[])
    implement.add_argument("--assurance-level", choices=["critical", "standard", "lightweight"],
                           default="critical")
    implement.add_argument("--method-proof-only", action="store_true",
                           help="run method synthesis and ESC without TLC; does not claim critical assurance")
    implement.add_argument("--clarifications",
                           help="authoritative concurrency assumptions used by critical TLC checking")
    implement.add_argument("--abstraction", choices=["atomic_operations", "lock_protocol"],
                           default="atomic_operations")
    implement.add_argument("--v2-reviewed-domain",
                           help="reviewed V2 JSON used by the generic refinement gate")
    implement.add_argument("--v2-validation-evidence",
                           help="hash-bound VALIDATED evidence for --v2-reviewed-domain")
    implement.add_argument("--parallel-wrapper", choices=["rayon"],
                           help="wrap a proved immutable scalar Rust kernel deterministically")
    implement.add_argument("--parallel-kernel", default="process_chunk",
                           help="proved Rust kernel name for --parallel-wrapper")
    implement.add_argument("--parallel-out", help="generated parallel Rust destination")
    implement.add_argument("--dependencies", choices=["stripe", "aws", "curl"],
                           help="fill a generated external adapter using a dependency SDK")

    check = sub.add_parser("verify", help="run OpenJML directly on a Java/JML source")
    check.add_argument("source")
    check.add_argument("--mode", choices=["parse", "check", "esc"], default="esc")
    check.add_argument("--json")
    check.add_argument("--backend", choices=["prusti", "kani"], default="prusti",
                       help="Rust verifier; ignored for Java and C")

    verify_refactor = sub.add_parser(
        "verify-refactor", help="prove a narrow Java/JML contract-preserving refactor")
    verify_refactor.add_argument("baseline", help="previously trusted Java/JML revision")
    verify_refactor.add_argument(
        "refactored", help="refactored Java/JML revision or multi-file source directory")
    verify_refactor.add_argument("--json", help="machine-readable evidence destination")
    verify_refactor.add_argument("--signing-key", help="GPG key ID for a detached verdict signature")

    optimize = sub.add_parser("optimize-algorithm", parents=[common],
                              help="rewrite a verified Java algorithm and re-run its proof gates")
    optimize.add_argument("source")
    optimize.add_argument("--strategy", choices=["hashmap", "two_pointer", "binary_search", "nested_loop"],
                          required=True)
    optimize.add_argument("--out", required=True)
    optimize.add_argument("--json")

    discover = sub.add_parser("discover-algorithms", parents=[common],
                              help="fan out verified algorithm strategy candidates")
    discover.add_argument("source")
    discover.add_argument("--out-dir", default="discovered")
    discover.add_argument("--strategies", default="all",
                          help="all or comma-separated strategy names")
    discover.add_argument("--max-workers", type=int, default=3)
    discover.add_argument("--json")

    security = sub.add_parser("assess-security", help="run formal CWE mapping and SAST assessment")
    security.add_argument("source")
    security.add_argument("--json")
    security.add_argument("--no-sast", action="store_true",
                          help="skip Semgrep; report is limited to formal evidence")
    security_inspect = sub.add_parser("security-inspect", help="inspect code for formal and SAST findings")
    security_inspect.add_argument("source")
    security_inspect.add_argument("--json")
    security_exploit = sub.add_parser("security-exploit", help="generate safe local JUnit PoC templates")
    security_exploit.add_argument("report")
    security_exploit.add_argument("target")
    security_exploit.add_argument("--out-dir", default="security-pocs")
    security_exploit.add_argument("--json")
    remediation = sub.add_parser("remediate", parents=[common],
                                 help="generate a verified defensive patch copy")
    remediation.add_argument("target")
    remediation.add_argument("report")
    remediation.add_argument("--out-dir", default="remediated")
    remediation.add_argument("--json")
    correction = sub.add_parser("correct-behavior", parents=[common],
                                help="strengthen a contract and prove a defensive behavior correction")
    correction.add_argument("target")
    correction.add_argument("--cwe", required=True)
    correction.add_argument("--strategy", choices=["bound-loop", "static-pool", "bounded-cache"],
                           help="capacity-bounding correction: rewrite unbounded loops or "
                                "dynamic structures into static bounded code (CWE-400)")
    correction.add_argument("--hardware", metavar="PROFILE.json",
                           help="hardware profile deriving physical capacity bounds "
                                "(SRAM/stack limits; mints HARDWARE_MEMORY_BOUND_PROVEN)")
    correction.add_argument("--struct-size-bytes", type=int,
                           help="explicit element size for --hardware capacity derivation")
    correction.add_argument("--out-dir", default="corrections")
    correction.add_argument("--max-attempts", type=int, default=3)
    correction.add_argument("--json")

    bisimulation = sub.add_parser("verify-bisimulation",
                                  help="validate a scoped state mapping without claiming equivalence")
    bisimulation.add_argument("baseline")
    bisimulation.add_argument("refactored")
    bisimulation.add_argument("mapping")
    bisimulation.add_argument("--json")

    inspect = sub.add_parser(
        "inspect", help="deterministically inspect one Java class for refactoring signals")
    inspect.add_argument("source", help="Java/JML source to inspect")
    inspect.add_argument("--json", help="machine-readable findings destination")

    apply_refactor = sub.add_parser(
        "apply-refactor", help="apply a hash-bound deterministic Java refactoring profile")
    apply_refactor.add_argument("source", help="baseline Java/JML source")
    apply_refactor.add_argument("--inspection",
                                help="hash-bound inspect JSON evidence (Java lanes)")
    apply_refactor.add_argument("--pattern", choices=["extract-method", "factory-method", "state", "decorator", "facade", "null-object", "strategy"],
                                default="extract-method")
    apply_refactor.add_argument("--method", required=True, help="inspected long method name")
    apply_refactor.add_argument("--out", required=True, help="same-named refactored Java path")
    apply_refactor.add_argument("--json", help="combined transformation/proof evidence")

    architecture = sub.add_parser("architecture", help="render typed IR and run bounded TLC")
    architecture.add_argument("stub")
    architecture.add_argument("--clarifications")
    architecture.add_argument("--abstraction", choices=["atomic_operations", "lock_protocol"],
                              default="atomic_operations")
    architecture.add_argument("--emit-tla")
    architecture.add_argument("--json")
    design = sub.add_parser("design-system",
                            help="generate a bounded architecture artifact from natural language")
    design.add_argument("requirement")
    design.add_argument("--provider", choices=["glm", "openai", "ollama"], default="ollama")
    design.add_argument("--out-file", default="architecture.json")
    design.add_argument("--json", help="machine-readable design evidence destination")
    design.add_argument("--timeout", type=int, default=120,
                        help="TLC timeout in seconds; bounds unbounded model attempts")
    design.add_argument("--max-attempts", type=int, default=3)
    design.add_argument("--staged", action="store_true",
                        help="use typed fragment elicitation and TLA/TLC publication gate")
    design.add_argument("--lang", choices=["java", "rust", "c", "cpp"], default="java",
                        help="target source language for deterministic component filenames")
    validate_arch = sub.add_parser("validate-architecture",
                                   help="validate unified staged architecture JSON with TLC")
    validate_arch.add_argument("artifact")
    validate_arch.add_argument("--json")
    validate_arch.add_argument("--timeout", type=int, default=120)

    domain = sub.add_parser("domain", parents=[common], help="elicit and scaffold a domain plugin")
    domain.add_argument("idea")
    domain.add_argument("--project-root", default=".")
    domain.add_argument("--force", action="store_true")
    domain.add_argument("--replace-reviewed-domain", action="store_true",
                        help="explicitly authorize replacing reviewed domain artifacts")
    domain.add_argument("--restart-clarifications", action="store_true",
                        help="discard saved domain answers and elicit a consistent set again")
    domain.add_argument("--schema-version", type=int, choices=[1, 2], default=1,
                        help="candidate schema; V2 is typed and uses validate-domain")
    validate_domain = sub.add_parser(
        "validate-domain", help="validate a typed V2 candidate with traversal and TLC")
    validate_domain.add_argument("name")
    validate_domain.add_argument("--project-root", default=".")
    validate_domain.add_argument("--emit-tla")
    promote = sub.add_parser("promote-domain", help="promote a reviewed candidate domain")
    promote.add_argument("name")
    promote.add_argument("--project-root", default=".")
    promote.add_argument("--replace-reviewed-domain", action="store_true")
    promote.add_argument("--schema-version", type=int, choices=[1, 2], default=None,
                         help="candidate schema; inferred from validated V2 evidence when omitted")
    promote.add_argument("--accept-candidate-sha256")
    promote.add_argument("--signing-key", help="GPG key ID for a detached promotion signature")
    compose = sub.add_parser(
        "compose", help="compose reviewed V2 domains and prove the glue with OpenJML ESC")
    compose.add_argument("artifact", help="composition artifact JSON path")
    compose.add_argument("--v2-dir", default=None,
                         help="reviewed V2 artifact directory (default domains/v2)")
    compose.add_argument("--out-dir", help="write the deterministic Java/JML sources here")
    compose.add_argument("--json", help="machine-readable verdict destination")
    compose.add_argument("--no-esc", action="store_true",
                         help="stop after the check gate; claims only STATIC_CHECK")
    compose.add_argument("--actors", help="comma-separated actor names for concurrent model preflight")
    compose.add_argument("--lang", choices=["java", "rust", "c", "cpp"], default="java",
                         help="composition lane: java renders JML + OpenJML; rust/c/cpp render"
                              " one native compilation unit proved by Prusti/Frama-C/ESBMC")
    reverify = sub.add_parser(
        "reverify", help="re-prove composition after a reviewed module changed")
    reverify.add_argument("artifact")
    reverify.add_argument("--changed-module", required=True,
                          help="reviewed V2 module whose contract changed")
    reverify.add_argument("--v2-dir", default=None)
    reverify.add_argument("--json")
    system = sub.add_parser(
        "system", help="verify isolated components in parallel, then prove composition")
    system.add_argument("artifact", help="system architecture and component-input JSON path")
    system.add_argument("--out-dir", required=True,
                        help="isolated component verdict and evidence directory")
    system.add_argument("--max-workers", type=int, default=4,
                        help="maximum concurrent component subprocesses")
    system.add_argument("--mode", choices=["implement", "refactor", "correct"], default="implement",
                        help="isolated implementation proofs, contract-preserving refactors, "
                             "or parallel behavior-correction sub-agents")
    system.add_argument("--provider", default="ollama",
                        help="LLM provider for correct-behavior sub-agents")
    system.add_argument("--model", default=None)
    system.add_argument("--max-attempts", type=int, default=3,
                        help="ESC repair attempts per correcting sub-agent")
    system.add_argument("--executable", default="formalspecgen",
                        help=argparse.SUPPRESS)
    system.add_argument("--json", help="aggregate machine-readable verdict destination")
    unified = sub.add_parser("unified-system", help="lower a unified architecture artifact")
    unified.add_argument("artifact")
    unified.add_argument("--evidence", required=True)
    unified.add_argument("--out-dir", required=True)
    unified.add_argument("--lang", choices=["java", "rust", "c", "cpp"], default="java")
    unified.add_argument("--v2-dir", default=None,
                         help="reviewed V2 directory for non-java composition lowering")
    unified.add_argument("--json")
    analyze = sub.add_parser("analyze-codebase", help="extract unreviewed architecture/domain candidates")
    analyze.add_argument("target_dir")
    analyze.add_argument("--out-dir", default="extracted")
    analyze.add_argument("--project-root", default=".")
    analyze.add_argument("--json")
    document = sub.add_parser("document-code", parents=[common],
                              help="document code as natural-language requirements from a formal V2 extraction")
    document.add_argument("source")
    document.add_argument("--out", required=True, help="Markdown documentation destination")
    document.add_argument("--project-root", default=".")
    document.add_argument("--no-llm", action="store_true",
                          help="skip the optional narrative pass; deterministic sections only")
    document.add_argument("--json")
    return parser


def dispatch(args: argparse.Namespace, ui: TerminalUI, store: SessionStore,
             state: dict[str, Any]) -> int:
    if args.command == "draft": return command_draft(args, ui, store, state)
    if args.command == "implement": return command_implement(args, ui)
    if args.command == "verify": return command_verify(args, ui)
    if args.command == "verify-refactor": return command_verify_refactor(args, ui)
    if args.command == "optimize-algorithm": return command_optimize_algorithm(args, ui)
    if args.command == "discover-algorithms": return command_discover_algorithms(args, ui)
    if args.command == "assess-security": return command_assess_security(args, ui)
    if args.command == "security-inspect": return command_security_inspect(args, ui)
    if args.command == "security-exploit": return command_security_exploit(args, ui)
    if args.command == "remediate": return command_remediate(args, ui)
    if args.command == "correct-behavior": return command_correct_behavior(args, ui)
    if args.command == "verify-bisimulation": return command_verify_bisimulation(args, ui)
    if args.command == "inspect": return command_inspect(args, ui)
    if args.command == "apply-refactor": return command_apply_refactor(args, ui)
    if args.command == "architecture": return command_architecture(args, ui)
    if args.command == "design-system": return command_design_system(args, ui)
    if args.command == "validate-architecture": return command_validate_architecture(args, ui)
    if args.command == "domain": return command_domain(args, ui, store, state)
    if args.command == "validate-domain": return command_validate_domain(args, ui)
    if args.command == "promote-domain": return command_promote_domain(args, ui)
    if args.command == "compose": return command_compose(args, ui)
    if args.command == "reverify": return command_reverify(args, ui)
    if args.command == "system": return command_system(args, ui)
    if args.command == "unified-system": return command_unified_system(args, ui)
    if args.command == "analyze-codebase": return command_analyze_codebase(args, ui)
    if args.command == "document-code": return command_document_code(args, ui)
    return 2


_REPL_COMMANDS = {"draft", "implement", "verify", "verify-refactor", "discover-algorithms", "inspect",
                  "apply-refactor", "architecture", "design-system", "domain",
                  "validate-domain", "promote-domain", "compose", "reverify", "system",
                  "document-code"}


def _repl_argv(line: str) -> list[str]:
    """Accept slash commands, ordinary subcommands, and pasted shell invocations."""
    text = line[1:].strip() if line.startswith("/") else line
    values = shlex.split(text)
    if values and values[0] == "formalspecgen":
        values = values[1:]
    if values and values[0] in _REPL_COMMANDS:
        return values
    return ["draft", line]


def _continued_line(first: str, ask: Callable[[str], str]) -> str:
    """Join shell-style trailing-backslash continuations before argument parsing."""
    parts = []
    current = first
    while current.rstrip().endswith("\\"):
        parts.append(current.rstrip()[:-1].rstrip())
        current = ask("... ")
    parts.append(current.strip())
    return " ".join(part for part in parts if part)


def repl(parser: argparse.ArgumentParser, ui: TerminalUI, store: SessionStore,
         state: dict[str, Any]) -> int:
    store.directory.mkdir(parents=True, exist_ok=True)
    session = PromptSession(history=FileHistory(str(store.history_path)))
    ui.console.print(Panel(
        "Enter a requirement to clarify and draft, or use /help.\n"
        "The LLM proposes; deterministic compilers transform; formal tools judge.",
        title="FormalSpecGen CLI", border_style="cyan"))
    while True:
        try:
            line = _continued_line(session.prompt("> ").strip(), session.prompt).strip()
        except (EOFError, KeyboardInterrupt):
            ui.console.print()
            return 0
        if not line: continue
        if line in {"/quit", "/exit"}: return 0
        if line == "/help":
            ui.console.print("/draft TEXT  /implement FILE  /verify FILE  /architecture FILE  "
                             "/domain TEXT  /validate-domain NAME  /session  /reset  /quit")
            continue
        if line == "/session":
            _write_json(state, None, ui.console); continue
        if line == "/reset":
            store.clear(); state.clear(); state.update(store.empty())
            ui.console.print("Session cleared."); continue
        argv = _repl_argv(line)
        try:
            args = parser.parse_args(argv)
            dispatch(args, ui, store, state)
        except SystemExit:
            continue
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = SessionStore(Path.cwd())
    state = store.load()
    ui = TerminalUI()
    code = dispatch(args, ui, store, state) if args.command else repl(parser, ui, store, state)
    if argv is None:
        raise SystemExit(code)
    return code


if __name__ == "__main__":
    main()
