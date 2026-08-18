"""Optional MCP façade for FormalSpecGen's structured verification workflows.

Install the optional SDK with ``pip install 'formalspecgen[mcp]'``.  The core functions in this
module remain importable without the SDK, which keeps the CLI and test environments lightweight.

Every tool confines its inputs AND outputs to the current workspace and returns
structured verdict objects; a tool failure is never converted into a success
claim.  Deliberately NOT exposed: ``promote-domain`` (hash-bound human
acceptance of reviewed artifacts is a trust action that stays with the CLI),
the interactive clarification wizards (``domain``, non-canonical ``draft``,
``design-system``), and the reviewer trust actions ``sign-artifact`` /
``manage-trust`` (signing and key policy require the human reviewer's own
GPG key — an agent must never sign or authorize on a reviewer's behalf).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Callable

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - exercised by environments without the optional SDK
    FastMCP = None

from pipeline import config
from pipeline.java_inspection import inspect_java_file
from pipeline.orchestrator import run_implementation_loop
from pipeline.verify import verify


def _workspace_path(value: str, *, must_exist: bool = True) -> Path:
    root = Path.cwd().resolve()
    path = Path(value).expanduser()
    path = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if root != path and root not in path.parents:
        raise ValueError("path must remain inside the current workspace")
    if must_exist and not path.exists():
        raise FileNotFoundError(str(path))
    return path


def _guarded(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run a tool body, converting path violations into fail-closed verdicts."""
    try:
        return call()
    except (ValueError, FileNotFoundError) as exc:
        message = str(exc)
        code = ("path_outside_workspace" if "workspace" in message
                else "input_unavailable" if isinstance(exc, FileNotFoundError)
                else "invalid_request")
        return {"status": "FAIL", "claim": "NO_PROOF", "code": code, "message": message}


def verify_code(file_path: str, mode: str = "esc") -> dict[str, Any]:
    """Verify Java, Rust, or C source and return a structured verdict."""
    path = _workspace_path(file_path)
    suffix = path.suffix.lower()
    if suffix in {".java", ".jml"}:
        exit_code, output = verify(path, mode=mode)
        return {"status": "VERIFIED" if exit_code == 0 else "VERIFY_FAILED",
                "claim": "DEDUCTIVE_PROOF" if exit_code == 0 and mode == "esc" else "NO_PROOF",
                "exit_code": exit_code, "mode": mode, "file": str(path), "output": output}
    if suffix == ".rs":
        from pipeline.verify_rust import verify_rust
        result = verify_rust(path.read_text(encoding="utf-8"), mode=mode, backend="prusti")
    elif suffix == ".c":
        from pipeline.verify_c import verify_c as verify_c_source
        result = verify_c_source(path.read_text(encoding="utf-8"), mode=mode)
    else:
        return {"status": "UNSUPPORTED_LANGUAGE", "claim": "NO_PROOF", "file": str(path)}
    return {"file": str(path), **result}


def validate_architecture(artifact_path: str, timeout: int = 120) -> dict[str, Any]:
    """Validate a unified architecture through its typed model and TLC gate."""
    from pipeline.architecture_tla_renderer import render_unified_architecture
    from pipeline.staged_architecture import UnifiedArchitecture
    from pipeline.architecture_tlc_gate import validate_architecture_with_tlc
    path = _workspace_path(artifact_path)
    try:
        architecture = UnifiedArchitecture.model_validate(json.loads(path.read_text(encoding="utf-8")))
        tla, cfg = render_unified_architecture(architecture)
        with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-") as directory:
            root = Path(directory)
            tla_path, cfg_path = root / "architecture.tla", root / "architecture.cfg"
            tla_path.write_text(tla, encoding="utf-8"); cfg_path.write_text(cfg, encoding="utf-8")
            result = validate_architecture_with_tlc(tla_path, cfg_path, config.TLC_JAR,
                                                    config.JAVA_BIN, timeout)
        return {"artifact": str(path), **result}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status": "ARCHITECTURE_INVALID", "claim": "NO_PROOF", "message": str(exc)}


def implement_code(spec_path: str, provider: str = "ollama",
                   assurance_level: str = "critical",
                   v2_reviewed_domain: str | None = None,
                   v2_validation_evidence: str | None = None) -> dict[str, Any]:
    """Run the native implementation loop for a workspace source/spec scaffold.

    Passing the reviewed-domain and validation-evidence pair enters the V2
    refinement gate: a native proof then binds to the promoted candidate
    hash and can mint SOURCE_MODEL_REFINEMENT.
    """
    from pipeline.orchestrator import run_implementation_loop
    def run() -> dict[str, Any]:
        domain = (_workspace_path(v2_reviewed_domain)
                  if v2_reviewed_domain is not None else None)
        evidence = (_workspace_path(v2_validation_evidence)
                    if v2_validation_evidence is not None else None)
        return run_implementation_loop(
            _workspace_path(spec_path), provider=provider,
            assurance_level=assurance_level,
            v2_reviewed_domain=domain, v2_validation_evidence=evidence)
    return _guarded(run)


def inspect_code(file_path: str) -> dict[str, Any]:
    """Run deterministic Java modernization inspection."""
    return inspect_java_file(_workspace_path(file_path))


def analyze_codebase(target_dir: str, out_dir: str = "extracted",
                     project_root: str = ".") -> dict[str, Any]:
    """Extract unreviewed architecture and V2 domain candidates from a source tree."""
    from pipeline.codebase_analysis import analyze_codebase as run_analysis
    return _guarded(lambda: run_analysis(
        _workspace_path(target_dir), _workspace_path(out_dir, must_exist=False),
        _workspace_path(project_root, must_exist=False)))


def document_code(source: str, out: str, project_root: str = ".",
                  no_llm: bool = False, provider: str = "ollama",
                  model: str | None = None) -> dict[str, Any]:
    """Document one source file as natural-language requirements (Code -> Math -> NL)."""
    from pipeline.code_documentation import document_code as run_documentation
    return _guarded(lambda: run_documentation(
        _workspace_path(source), _workspace_path(out, must_exist=False),
        project_root=str(_workspace_path(project_root, must_exist=False)),
        provider=provider, model=model, no_llm=no_llm))


def assess_security(source: str, run_sast: bool = True) -> dict[str, Any]:
    """Assess a Java source against formal verification and Semgrep SAST evidence."""
    from pipeline.security_assessment import assess_security as run_assessment
    return _guarded(lambda: run_assessment(_workspace_path(source), run_sast=run_sast))


def security_inspect(source: str) -> dict[str, Any]:
    """Inspect sources (file or directory) for findings mapped to CWEs."""
    from pipeline.security_poc import inspect_security as run_inspection
    return _guarded(lambda: run_inspection(_workspace_path(source)))


def security_exploit(report_path: str, target: str,
                     out_dir: str = "security-pocs") -> dict[str, Any]:
    """Generate review-only PoC source templates from an inspection report."""
    from pipeline.security_poc import generate_pocs as run_pocs
    return _guarded(lambda: run_pocs(
        _workspace_path(report_path), _workspace_path(target),
        _workspace_path(out_dir, must_exist=False)))


def remediate_code(target: str, report: str, out_dir: str = "remediated",
                   provider: str = "ollama", model: str | None = None) -> dict[str, Any]:
    """Generate a patched copy from a vulnerability report and prove it with ESC."""
    from pipeline.remediation import remediate as run_remediation
    return _guarded(lambda: run_remediation(
        _workspace_path(target), _workspace_path(report),
        _workspace_path(out_dir, must_exist=False), provider=provider, model=model))


def correct_behavior(target: str, cwe: str, out_dir: str = "corrections",
                     provider: str = "ollama", model: str | None = None,
                     max_attempts: int = 3, strategy: str | None = None,
                     hardware: str | None = None,
                     struct_size_bytes: int | None = None,
                     auto_strategy: bool = False) -> dict[str, Any]:
    """Strengthen a contract per CWE and prove the corrected behavior with ESC.

    ``strategy`` selects one of the nine deterministic corrections (four
    capacity-bounding strategies for CWE-400 plus the five hardening
    strategies); ``hardware`` + ``struct_size_bytes`` derive the capacity
    from silicon; ``auto_strategy`` routes the strategy from the code's
    own shape (CWE-scoped, explicit opt-in).
    """
    from pipeline.behavior_correction import correct_behavior as run_correction
    profile = _workspace_path(hardware) if hardware is not None else None
    return _guarded(lambda: run_correction(
        _workspace_path(target), cwe, _workspace_path(out_dir, must_exist=False),
        provider=provider, model=model, max_attempts=max_attempts,
        strategy=strategy, hardware=profile,
        struct_size_bytes=struct_size_bytes, auto_strategy=auto_strategy))


def architecture(stub_path: str, abstraction: str = "atomic_operations",
                 clarifications: str = "") -> dict[str, Any]:
    """Check a bounded JML architecture abstraction with the real TLC gate."""
    from pipeline.tla_backend import generate_and_check
    code = _workspace_path(stub_path).read_text(encoding="utf-8")
    return _guarded(lambda: generate_and_check(
        code, clarifications=clarifications, abstraction=abstraction))


def system(plan_path: str, mode: str = "implement", out_dir: str = "runs/system",
           max_workers: int = 4) -> dict[str, Any]:
    """Run the parallel system orchestrator over an architecture artifact.

    Modes mirror the CLI: ``implement`` (isolated component proofs plus the
    composition gate), ``refactor`` (bounded extract-method modernization),
    and ``correct`` (isolated one-CWE-per-subagent hardening sub-agents).
    """
    from pipeline import system_orchestrator
    def dispatch() -> dict[str, Any]:
        plan = _workspace_path(plan_path)
        destination = _workspace_path(out_dir, must_exist=False)
        if mode == "implement":
            return system_orchestrator.verify_system(plan, out_dir=destination,
                                                     max_workers=max_workers)
        if mode == "refactor":
            return system_orchestrator.refactor_system(plan, out_dir=destination,
                                                       max_workers=max_workers)
        if mode == "correct":
            return system_orchestrator.correct_system(plan, out_dir=destination,
                                                      max_workers=max_workers)
        raise ValueError(f"unknown system mode {mode!r}: expected implement, "
                         "refactor, or correct")
    return _guarded(dispatch)


def apply_refactor(source: str, inspection: str, pattern: str, method: str,
                   out: str) -> dict[str, Any]:
    """Apply one hash-bound refactor profile and immediately run its proof gate."""
    from pipeline.refactor_actions import apply_refactor as run_apply
    return _guarded(lambda: run_apply(
        _workspace_path(source), _workspace_path(inspection), pattern, method,
        _workspace_path(out, must_exist=False)))


def verify_refactor(baseline: str, refactored: str) -> dict[str, Any]:
    """Prove a contract-preserving refactor (file -> single-file gate, dir -> multifile)."""
    def run() -> dict[str, Any]:
        from pipeline.refactor_gate import (
            verify_contract_preserving_refactor, verify_multifile_contract_refactor)
        base = _workspace_path(baseline)
        target = _workspace_path(refactored)
        if target.is_dir():
            return verify_multifile_contract_refactor(base, target)
        return verify_contract_preserving_refactor(base, target)
    return _guarded(run)


def verify_bisimulation(baseline: str, refactored: str, mapping: str) -> dict[str, Any]:
    """Validate a bisimulation preflight mapping without claiming equivalence."""
    from pipeline.bisimulation import verify_bisimulation_inputs as run_bisimulation
    return _guarded(lambda: run_bisimulation(
        _workspace_path(baseline), _workspace_path(refactored), _workspace_path(mapping)))


def optimize_algorithm(source: str, out: str, strategy: str,
                       provider: str = "ollama", model: str | None = None) -> dict[str, Any]:
    """Request a constrained algorithm rewrite and re-run ESC plus the refactor gate."""
    from pipeline.algorithm_optimization import optimize_algorithm as run_optimize
    return _guarded(lambda: run_optimize(
        _workspace_path(source), _workspace_path(out, must_exist=False),
        strategy=strategy, provider=provider, model=model))


def discover_algorithms(source: str, out_dir: str = "discovered",
                        strategies: list[str] | None = None, provider: str = "ollama",
                        model: str | None = None, max_workers: int = 3) -> dict[str, Any]:
    """Fan a specification out across strategy prompts, keeping ESC-verified candidates."""
    from pipeline.algorithm_discovery import discover_algorithms as run_discovery
    return _guarded(lambda: run_discovery(
        _workspace_path(source), _workspace_path(out_dir, must_exist=False),
        strategies=strategies, provider=provider, model=model, max_workers=max_workers))


def validate_domain(name: str, project_root: str = ".",
                    timeout: int | None = None) -> dict[str, Any]:
    """Validate a V2 domain candidate with the bounded traverser and real TLC."""
    def run() -> dict[str, Any]:
        from pipeline.domain_v2_validation import validate_domain as run_validation
        try:
            root = _workspace_path(project_root, must_exist=False)
        except (ValueError, FileNotFoundError):
            raise  # path violations stay path failures, not validation failures
        try:
            evidence = run_validation(name, project_root=str(root), timeout=timeout)
        except Exception as exc:  # validation failures are evidence, not crashes
            return {"status": "VALIDATION_FAILED", "claim": "NO_PROOF",
                    "message": str(exc)[:400]}
        return {"status": "VALIDATED", "claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
                **evidence.model_dump(mode="json")}
    return _guarded(run)


def compose(artifact_path: str, v2_dir: str | None = None, run_esc: bool = True,
            actors: list[str] | None = None) -> dict[str, Any]:
    """Compose reviewed V2 domains and prove the glue with OpenJML ESC."""
    def run() -> dict[str, Any]:
        from pipeline.composition_render import verify_composition
        value = json.loads(_workspace_path(artifact_path).read_text(encoding="utf-8"))
        resolved = _workspace_path(v2_dir) if v2_dir else None
        return verify_composition(json.dumps(value), resolved, run_esc=run_esc, actors=actors)
    return _guarded(run)


def reverify_composition(artifact_path: str, changed_module: str,
                         v2_dir: str | None = None, run_esc: bool = True) -> dict[str, Any]:
    """Re-prove composition after a reviewed module contract changed."""
    def run() -> dict[str, Any]:
        from pipeline.composition_render import reverify_composition as run_reverify
        value = json.loads(_workspace_path(artifact_path).read_text(encoding="utf-8"))
        resolved = _workspace_path(v2_dir) if v2_dir else None
        return run_reverify(json.dumps(value), changed_module, resolved, run_esc=run_esc)
    return _guarded(run)


def unified_system(artifact_path: str, evidence_path: str, out_dir: str,
                   language: str = "java") -> dict[str, Any]:
    """Lower a validated unified architecture into sources and prove the core."""
    from pipeline.unified_system_runner import run_unified_system as run_lowering
    return _guarded(lambda: run_lowering(
        _workspace_path(artifact_path), _workspace_path(evidence_path),
        _workspace_path(out_dir, must_exist=False), language=language))


def draft_canonical_contract(domain: str, lang: str = "java", out_file: str | None = None,
                             project_root: str = ".", requirement: str = "") -> dict[str, Any]:
    """Deterministically lower a reviewed V2 domain into Java/JML, Rust, C, or C++."""
    def run() -> dict[str, Any]:
        from pipeline.canonical_draft import canonical_draft
        resolved_out = str(_workspace_path(out_file, must_exist=False)) if out_file else None
        return canonical_draft(domain, lang=lang, out_file=resolved_out,
                               project_root=str(_workspace_path(
                                   project_root, must_exist=False)),
                               requirement=requirement)
    return _guarded(run)


def prove_equivalence(baseline: str, refactored: str,
                      mapping: str) -> dict[str, Any]:
    """Prove bounded behavioral bisimulation between two V2 machines."""
    from pipeline.equivalence import prove_equivalence as run_proof
    return _guarded(lambda: run_proof(
        _workspace_path(baseline), _workspace_path(refactored),
        _workspace_path(mapping)))


def generate_traceability_matrix(domain: str, source: str,
                                 requirements: str,
                                 out: str = "traceability-matrix.md") -> dict[str, Any]:
    """Map REQ-### requirements to V2 invariants and source lines."""
    from pipeline.traceability import (
        generate_traceability_matrix as run_matrix, write_matrix,
    )
    def run() -> dict[str, Any]:
        matrix = run_matrix(_workspace_path(domain),
                            _workspace_path(source),
                            _workspace_path(requirements))
        path = write_matrix(matrix, _workspace_path(out, must_exist=False))
        return {"status": "TRACEABILITY_GENERATED",
                "matrix_file": str(path), **matrix}
    return _guarded(run)


def verify_unbounded(source: str, invariant: str | None = None,
                     provider: str = "ollama") -> dict[str, Any]:
    """Prove a loop invariant inductive (k-induction, no unrolling)."""
    from pipeline.unbounded import verify_unbounded as run_unbounded
    return _guarded(lambda: run_unbounded(
        _workspace_path(source), invariant=invariant, provider=provider))


def verify_linearizability(source: str, domain: str) -> dict[str, Any]:
    """Java lock correspondence plus bounded-history linearizability."""
    from pipeline.linearizability import (
        verify_linearizability as run_linearizability,
    )
    return _guarded(lambda: run_linearizability(
        _workspace_path(source), _workspace_path(domain)))


def verify_distributed(domain: str, message_fields: str,
                       faults: str = "message_loss,duplication,reordering"
                       ) -> dict[str, Any]:
    """Safety under injected network faults (comma-separated fields/faults)."""
    from pipeline.distributed import verify_distributed as run_distributed
    def run() -> dict[str, Any]:
        fields = [item.strip() for item in message_fields.split(",") if item.strip()]
        fault_list = [item.strip() for item in faults.split(",") if item.strip()]
        return run_distributed(_workspace_path(domain),
                               faults=fault_list, message_fields=fields)
    return _guarded(run)


def verify_heap(source: str, provider: str = "ollama") -> dict[str, Any]:
    """Unbounded heap-shape verification via ghost predicates (Rust only)."""
    from pipeline.heap import verify_heap as run_heap
    return _guarded(lambda: run_heap(_workspace_path(source),
                                     provider=provider))


def create_server():
    if FastMCP is None:
        raise RuntimeError("MCP SDK is not installed; install with: pip install 'formalspecgen[mcp]'")
    server = FastMCP("FormalSpecGen")
    for tool in (verify_code, validate_architecture, implement_code, inspect_code,
                 analyze_codebase, document_code, assess_security, security_inspect,
                 security_exploit, remediate_code, correct_behavior, apply_refactor,
                 verify_refactor, verify_bisimulation, optimize_algorithm,
                 discover_algorithms, validate_domain, compose, reverify_composition,
                 unified_system, draft_canonical_contract, architecture, system,
                 prove_equivalence, generate_traceability_matrix, verify_unbounded,
                 verify_linearizability, verify_distributed, verify_heap):
        server.tool()(tool)
    return server


if __name__ == "__main__":
    create_server().run()
