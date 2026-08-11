# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Orchestrator: NL -> generate JML stub -> `openjml -check` -> bounded repair loop -> verdict.

Mirrors formalspecDD's orchestrator shape; the per-attempt work differs (we DRAFT JML and
validate with -check, vs. DD fills Java bodies and validates with -esc). Strategy and
stall detection are reused verbatim from DD. Every attempt is recorded and surfaced to
the human — we never silently trust a final "validated" signal (design-critique guardrail).

Usage:
  python -m pipeline.orchestrator "The bank account must not allow withdrawals exceeding the balance."
"""
import argparse
import json
import re
import subprocess
import time
from dataclasses import asdict
from pathlib import Path

from . import config, strategy, jml_io
from .schemas import Attempt, SpecResult, VC
from .parse_check import parse_check
from .verify import verify, classify
from .llm import glm_generate_spec, glm_repair_spec, _chat_fn, LLMError
from .spec_lint import lint_spec, blocking_findings
from .explain_vc import explain_vc
from .lifecycle import (EvidenceClaim, GateRecord, PipelineState, RunLedger,
                        command_version, failure_fingerprint, sha256_text)
from .workspace_contracts import contract_context


def run_implementation_loop(file_path: str | Path, provider: str = "glm",
                            assurance_level: str = "critical",
                            method_proof_only: bool = False,
                            v2_reviewed_domain: str | Path | None = None,
                            v2_validation_evidence: str | Path | None = None,
                            **kwargs) -> dict:
    """Route a trusted source scaffold to its native synthesis and verification loop."""
    source = Path(file_path)
    code = source.read_text(encoding="utf-8")
    suffix = source.suffix.lower()
    if suffix in {".java", ".jml"}:
        if method_proof_only:
            from .implementation import synthesize_implementation
            kwargs.pop("clarifications", None)
            kwargs.pop("abstraction", None)
            result = synthesize_implementation(code, provider=provider,
                                               verification_mode="esc", **kwargs)
            result["assurance_level_requested"] = assurance_level
            result["assurance_scope"] = "method_contract_only"
            result["bounded_architecture_checked"] = False
            result["source_refinement_proved"] = False
            return result
        from .profile import run_assured_implementation
        return run_assured_implementation(code, assurance_level=assurance_level,
            provider=provider, v2_reviewed_domain=v2_reviewed_domain,
            v2_validation_evidence=v2_validation_evidence, **kwargs)
    if suffix in {".rs", ".c"}:
        if v2_reviewed_domain or v2_validation_evidence:
            raise ValueError("generic V2 refinement currently supports Java/JML only")
        from .polyglot_implementation import synthesize_polyglot_implementation
        language = "rust" if suffix == ".rs" else "c"
        mode = "esc" if assurance_level == "critical" else "check"
        kwargs.pop("clarifications", None)
        kwargs.pop("abstraction", None)
        result = synthesize_polyglot_implementation(
            code, language=language, provider=provider, verification_mode=mode,
            runtime_gate=assurance_level in {"critical", "standard"}, **kwargs)
        result["assurance_level_requested"] = assurance_level
        if method_proof_only:
            result["assurance_scope"] = "method_contract_only"
            result["bounded_architecture_checked"] = False
            result["source_refinement_proved"] = False
        if assurance_level == "standard":
            runtime = result.get("runtime_evidence") or {}
            if (result.get("final_status") == "STATIC_CHECKED" and
                    runtime.get("status") == "NO_RUNTIME_FAILURE_FOUND"):
                result["final_status"] = "STATIC_CHECKED_RUNTIME_TESTED"
                result["claim"] = "RUNTIME_SAMPLE"
            else:
                result["assurance_note"] = (
                    "Standard assurance requires a passing instrumented runtime sample.")
        return result
    raise ValueError(f"unsupported synthesis target: {suffix or '<none>'}")


def _norm_usage(u):
    return {"input": u.get("prompt_tokens", 0), "output": u.get("completion_tokens", 0),
            "total": u.get("total_tokens", 0)}


def _add(tot, u):
    tot["input"] += u.get("input", 0)
    tot["output"] += u.get("output", 0)
    tot["total"] += u.get("total", 0)


def _slug(s, n=24):
    s = re.sub(r'[^a-zA-Z0-9]+', '-', s).strip('-').lower()
    return s[:n] or "spec"


def _reviewed_domain_findings(nl: str, stub: str) -> list[dict]:
    if not re.search(r"\btraffic[- ]light\b", nl, re.I):
        return []
    from .domains.traffic_light_controller_extract import (
        diagnose_traffic_light_boundary, recognizes_traffic_light_controller,
    )
    if recognizes_traffic_light_controller(stub):
        return []
    mismatches = diagnose_traffic_light_boundary(stub)
    return [{
        "line": 1,
        "code": "domain-contract-mismatch",
        "message": ("Traffic-light draft does not match the reviewed architecture API: "
                    + "; ".join(mismatches or ["complete six-action API required"])),
        "advice": ("Use fields ns_light/ew_light and exactly turnNsGreen, "
                   "turnNsYellow, turnNsRed, turnEwGreen, turnEwYellow, turnEwRed "
                   "with strict opposing-red green guards."),
        "severity": "error",
    }]


def _gen(nl, model, provider, fallback):
    """Generate via `provider`; on LLMError (e.g. GLM 524/empty) retry on `fallback`."""
    try:
        return glm_generate_spec(nl, model=model, chat_fn=_chat_fn(provider))
    except LLMError:
        if fallback and fallback != provider:
            return glm_generate_spec(nl, model=model, chat_fn=_chat_fn(fallback))
        raise


def _repair(prev_stub, prev_text, nl, model, provider, fallback):
    try:
        return glm_repair_spec(prev_stub, prev_text, nl, model=model, chat_fn=_chat_fn(provider))
    except LLMError:
        if fallback and fallback != provider:
            return glm_repair_spec(prev_stub, prev_text, nl, model=model, chat_fn=_chat_fn(fallback))
        raise


def _check_attempt(attempt_dir, stub, fallback_name):
    """Write stub to <ClassName>.java, run -check, return (exit, text, vcs, path).

    Refuses to validate a draft with no parseable `public class`: `openjml -check` on an
    empty/garbage file returns exit 0, which would otherwise produce a FAKE 'VERIFIED'.
    """
    cname = jml_io.class_name(stub)
    if not stub.strip() or cname is None:
        p = attempt_dir / f"{fallback_name}.java"
        p.write_text(stub or "", encoding="utf-8")
        msg = "model output had no usable Java class (empty/truncated); refused to validate"
        (attempt_dir / "check.log").write_text("<" + msg + ">", encoding="utf-8")
        return 1, "<" + msg + ">", [VC(file=fallback_name + ".java", line=0,
                                      category="error", detail=msg, raw=msg)], p
    p = attempt_dir / f"{cname}.java"
    p.write_text(stub, encoding="utf-8")
    classes = attempt_dir / "javac-classes"
    classes.mkdir(exist_ok=True)
    try:
        compiled = subprocess.run([config.JAVAC, "-d", str(classes), str(p)],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=config.CHECK_TIMEOUT)
        javac_text = (compiled.stdout or "") + (compiled.stderr or "")
        javac_gate = {"exit_code": compiled.returncode, "output": javac_text[-4000:]}
    except subprocess.TimeoutExpired:
        javac_gate = {"exit_code": 124, "output": "javac timed out"}
    except FileNotFoundError as exc:
        javac_gate = {"exit_code": 127, "output": f"javac not found: {exc}"}
    (attempt_dir / "javac-gate.json").write_text(
        json.dumps(javac_gate, indent=2, ensure_ascii=False), encoding="utf-8")
    if javac_gate["exit_code"] != 0:
        text = "OpenJML skipped because javac gate failed.\n" + javac_gate["output"]
        (attempt_dir / "check.log").write_text(text, encoding="utf-8")
        vcs = parse_check(javac_gate["output"])
        if not vcs:
            vcs = [VC(file=p.name, line=0, category="Javac",
                      detail=javac_gate["output"][:1000], raw=javac_gate["output"][:1000])]
        return javac_gate["exit_code"], text, vcs, p
    code_exit, text = verify(p, mode="check")
    (attempt_dir / "check.log").write_text(text, encoding="utf-8")
    vcs = parse_check(text) if code_exit != 0 else []
    # Guarantee a non-empty fingerprint even if -check's format wasn't recognized,
    # so strategy.is_stalled still detects repeats/oscillation.
    if code_exit != 0 and not vcs and text.strip():
        vcs = [VC(file=cname + ".java", line=0, category="check",
                  detail=text.strip()[:200], raw=text.strip()[:200])]
    return code_exit, text, vcs, p


def run(nl, provider="glm", fallback_provider=None, out_dir=None, model=None,
        max_attempts=None, on_event=None, resample_budget=None, feedback_budget=None,
        workspace_files=None):
    """Run the synchronous drafting pipeline.

    ``on_event`` is an optional, synchronous callback used by interactive clients.  It
    deliberately does not change the CLI execution model; callers that need async I/O
    can run this function in a worker and forward these small event dictionaries.
    """
    def emit(event_type, **payload):
        if on_event is not None:
            on_event({"type": event_type, **payload})

    original_nl = nl
    nl, retrieved_contracts = contract_context(nl, workspace_files or {})
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(out_dir) if out_dir else config.ROOT / "runs" / _slug(nl) / ts
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = RunLedger(out_dir, on_event)

    t0 = time.time()
    used_model = model or config.GLM_MODEL
    tot = {"input": 0, "output": 0, "total": 0}
    result = SpecResult(nl=original_nl, final_status="UNKNOWN", model=used_model,
                        provider=provider, attempts=[], tokens=tot)
    history = []          # (stub, vcs, check_text)
    assumptions, missing = [], []
    emit("progress", stage="starting", message="Starting specification draft")
    ledger.record(PipelineState.REQUIREMENTS, "ACCEPTED", claim=EvidenceClaim.TRANSFORMATION,
                  details={"requirement_hash": sha256_text(original_nl),
                           "workspace_contracts": len(retrieved_contracts)},
                  evidence={"requirement": original_nl,
                            "workspace_contracts": retrieved_contracts})
    ledger.record(PipelineState.CONTRACT, "DRAFTING", claim=EvidenceClaim.TRANSFORMATION,
                  details={"locked_contract_policy": "LLM may propose; human-reviewed clauses are authoritative"})

    samples_done = feedback_done = 0
    while True:
        last_verified = bool(result.attempts) and result.attempts[-1].status == "VERIFIED"
        dec = strategy.decide(history, last_verified, samples_done, feedback_done, max_attempts,
                              resample_budget, feedback_budget)
        if dec.action == "stop":
            result.final_status = result.attempts[-1].status if result.attempts else "NO_ATTEMPT"
            result.stop_reason = dec.reason
            suspect = strategy.ambiguity_suspected(history)
            if suspect and result.final_status != "VERIFIED":
                result.stop_reason += f"; NL_AMBIGUITY_SUSPECTED {suspect}"
            break

        n = len(result.attempts) + 1
        adir = out_dir / f"attempt{n}"; adir.mkdir(exist_ok=True)
        emit("progress", stage=dec.action, attempt=n,
             message=("Generating specification" if dec.action == "sample"
                      else "Repairing specification from diagnostics"))
        try:
            if dec.action == "sample":
                draft, used_model, usage = _gen(nl, model, provider, fallback_provider)
                samples_done += 1
            else:  # feedback
                prev_stub, _pv, prev_text = history[-1]
                draft, used_model, usage = _repair(prev_stub, prev_text, nl, model, provider, fallback_provider)
                feedback_done += 1
        except LLMError as e:
            note = f"[{e.code}] {e.message}" + (f" (HTTP {e.http_status})" if e.http_status else "")
            result.attempts.append(Attempt(n=n, exit_code=-2, status="API_ERROR", note=note))
            result.final_status, result.stop_reason = "API_ERROR", f"LLMError [{e.code}]"
            emit("error", stage="generation", attempt=n, message=note)
            break

        result.model = used_model
        draft.stub = jml_io.normalize_line_clause_continuations(draft.stub)
        draft.stub = jml_io.normalize_old_in_requires(draft.stub)
        candidate_hash = sha256_text(draft.stub)
        un = _norm_usage(usage); _add(tot, un)
        assumptions += [a for a in draft.assumptions if a not in assumptions]
        missing += [q for q in draft.missing_info if q not in missing]

        emit("spec_draft", attempt=n, code=draft.stub,
             assumptions=draft.assumptions, missing_info=draft.missing_info)
        candidate_transition = ledger.record(PipelineState.CANDIDATE, "PROPOSED",
            claim=EvidenceClaim.TRANSFORMATION,
            details={"attempt": n, "strategy": dec.action, "candidate_hash": candidate_hash},
            evidence={"source": draft.stub, "model": used_model, "tokens": un})
        lint_warnings = lint_spec(draft.stub)
        lint_warnings.extend(_reviewed_domain_findings(original_nl, draft.stub))
        for warning in lint_warnings:
            emit("spec_warning", attempt=n, **warning)
        emit("progress", stage="checking", attempt=n,
             message="Checking JML syntax and types with OpenJML")
        code_exit, text, vcs, p = _check_attempt(adir, draft.stub, fallback_name=f"Draft{n}")
        blockers = blocking_findings(lint_warnings) if code_exit == 0 else []
        if blockers:
            lint_text = "\n".join(
                f"{p.name}:{warning['line']}: specification lint [{warning['code']}]: "
                f"{warning['message']} Suggested repair: {warning['advice']}"
                for warning in blockers)
            text = "OpenJML syntax/type check passed.\n" + lint_text
            vcs = [VC(file=p.name, line=warning["line"], category="SpecLint",
                      detail=f"[{warning['code']}] {warning['message']} {warning['advice']}",
                      raw=warning["message"])
                   for warning in blockers]
            (adir / "check.log").write_text(text, encoding="utf-8")
        javac_path = adir / "javac-gate.json"
        javac = json.loads(javac_path.read_text(encoding="utf-8")) if javac_path.exists() else None
        javac_failed = bool(javac and javac["exit_code"] != 0)
        if javac_failed:
            detail = javac.get("output", "javac rejected candidate")[-1000:]
            vcs = [VC(file=p.name, line=0, category="Javac", detail=detail, raw=detail)]
            text = "javac gate failed before formal validation:\n" + detail
        note = dec.action + f" ({dec.reason})"
        attempt_status = ("COMPILE_FAILED" if javac_failed else
                          "SPEC_LINT_FAILED" if blockers else classify(code_exit))
        attempt_exit = javac["exit_code"] if javac_failed else -3 if blockers else code_exit
        gates = [
            GateRecord("java_structure", 1, "PASS" if jml_io.class_name(draft.stub) else "FAIL",
                       evidence_path=str(p)),
            GateRecord("javac", 2,
                       ("PASS" if javac and javac["exit_code"] == 0 else
                        "SKIPPED" if javac is None else "FAIL"),
                       reason=("test/mocked checker did not emit javac evidence" if javac is None
                               else javac.get("output", "")[-300:]),
                       evidence_path=str(javac_path) if javac else ""),
            GateRecord("spec_lint", 3, "FAIL" if blockers else "PASS",
                       reason=f"{len(blockers)} blocking finding(s)"),
            GateRecord("openjml_check", 4, "PASS" if code_exit == 0 else "FAIL",
                       reason=classify(code_exit), evidence_path=str(adir / "check.log")),
            GateRecord("rac_quick_test", 5, "SKIPPED",
                       reason="contract drafting has no trusted implementation to execute"),
        ]
        fingerprints = [failure_fingerprint("openjml", vc.category, vc.method, vc.line,
                                            vc.detail or vc.raw) for vc in vcs]
        gate_transition = ledger.record(PipelineState.CHEAP_GATES, attempt_status,
            claim=EvidenceClaim.STATIC_CHECK,
            details={"attempt": n, "candidate_hash": candidate_hash,
                     "failure_fingerprints": fingerprints},
            evidence={"gates": [asdict(gate) for gate in gates], "diagnostic": text[-8000:]})
        result.attempts.append(Attempt(n=n, exit_code=attempt_exit, status=attempt_status,
                                       vcs=vcs, note=note, tokens=un,
                                       candidate_hash=candidate_hash,
                                       failure_fingerprints=fingerprints,
                                       gates=[asdict(gate) for gate in gates],
                                       evidence=[candidate_transition.evidence_path,
                                                 gate_transition.evidence_path]))
        history.append((draft.stub, vcs, text))
        result.stub_path = str(p)
        for vc in vcs:
            explanation = explain_vc(vc.category, vc.detail or vc.raw)
            emit("vc_failure", attempt=n, file=vc.file, line=vc.line,
                 category=vc.category, method=vc.method, declaration=vc.decl,
                 message=vc.detail or vc.raw, **explanation)
        emit("attempt_complete", attempt=n, status=result.attempts[-1].status,
             exit_code=attempt_exit, failures=len(vcs), note=note)
        if result.attempts[-1].status in {"TOOL_ERROR", "TOOL_MISSING"}:
            result.final_status = result.attempts[-1].status
            result.stop_reason = ("OpenJML installation/configuration failed; candidate repair "
                                  "is disabled because this diagnostic is not about the contract")
            break
        if result.attempts[-1].status == "VERIFIED":
            result.final_status, result.stop_reason = "VERIFIED", "openjml -check clean"
            break

    result.assumptions, result.missing_info = assumptions, missing
    result.duration_s = time.time() - t0
    final_source = (Path(result.stub_path).read_text(encoding="utf-8") if result.stub_path and
                    Path(result.stub_path).exists() else "")
    proof_status = "SKIPPED" if result.final_status == "VERIFIED" else "NOT_REACHED"
    ledger.record(PipelineState.PROOF, proof_status, claim=EvidenceClaim.NO_PROOF,
        details={"reason": "draft validation proves syntax/types only; implementation ESC was not run"})
    result.provenance = {
        "source_sha256": sha256_text(final_source),
        "contract_sha256": sha256_text("\n".join(sorted(jml_io.extract_clauses(final_source)))),
        "requirement_sha256": sha256_text(original_nl),
        "backend": "openjml",
        "tool_version": command_version([config.OPENJML, "--version"]),
        "command": [config.OPENJML, "-check", result.stub_path],
        "bounds": None,
        "abstraction": "jml_contract_draft",
        "source_refinement_proved": False,
    }
    result.provenance["tool_versions"] = {"openjml": result.provenance["tool_version"]}
    ledger.record(PipelineState.REVIEW_AND_MEASURE, result.final_status,
        claim=EvidenceClaim.STATIC_CHECK,
        details={"stop_reason": result.stop_reason, "attempts": len(result.attempts)},
        evidence={"provenance": result.provenance, "token_usage": result.tokens})
    result.pipeline_state = PipelineState.REVIEW_AND_MEASURE.value
    result.transitions = [asdict(item) for item in ledger.transitions]
    _finalize(out_dir, result)
    _summary(result, out_dir)
    emit("verified" if result.final_status == "VERIFIED" else "complete",
         status=result.final_status, stop_reason=result.stop_reason,
         attempts=len(result.attempts), duration_s=round(result.duration_s, 3),
         pipeline_state=result.pipeline_state, claim=result.claim,
         provenance=result.provenance,
         code=(Path(result.stub_path).read_text(encoding="utf-8") if result.stub_path and
               Path(result.stub_path).exists() else ""),
         assumptions=result.assumptions, missing_info=result.missing_info)
    return result


def _finalize(out_dir, result):
    (out_dir / "verdict.json").write_text(
        json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")


def _summary(result, out_dir):
    print(f"[formalspecgen] {result.final_status}  ({len(result.attempts)} attempt(s), "
          f"stop=\"{result.stop_reason}\", model={result.model}, "
          f"tokens={result.tokens.get('total', 0)}, {result.duration_s:.1f}s)")
    for a in result.attempts:
        vc = f" errs={len(a.vcs)}" if a.vcs else ""
        print(f"    #{a.n} {a.status} (exit={a.exit_code}{vc}) [{a.note}]")
    if result.assumptions:
        print("    assumptions:")
        for s in result.assumptions:
            print(f"      - {s}")
    if result.missing_info:
        print("    open questions for the human:")
        for q in result.missing_info:
            print(f"      ? {q}")
    print(f"    run dir: {out_dir}")


def main():
    ap = argparse.ArgumentParser(description="formalspecgen orchestrator (NL -> validated JML)")
    ap.add_argument("nl", help="natural-language requirement (quote it)")
    ap.add_argument("--model", default=None, help=f"model id (default {config.GLM_MODEL})")
    ap.add_argument("--max-attempts", type=int, default=None,
                    help=f"cap (default {strategy.MAX_ATTEMPTS})")
    ap.add_argument("--resample-budget", type=int, default=None,
                    help=f"fresh-generation budget (default {strategy.RESAMPLE_BUDGET})")
    ap.add_argument("--feedback-budget", type=int, default=None,
                    help=f"diagnostic-feedback budget (default {strategy.FEEDBACK_BUDGET})")
    ap.add_argument("--provider", default="glm", choices=["glm", "openai", "ollama"],
                    help="primary LLM provider (default glm)")
    ap.add_argument("--fallback-provider", default=None, choices=["glm", "openai", "ollama"],
                    help="retry on this provider if the primary fails (e.g. --fallback-provider openai)")
    ap.add_argument("--out", default=None, help="output dir (default runs/<slug>/<timestamp>)")
    args = ap.parse_args()
    run(args.nl, provider=args.provider, fallback_provider=args.fallback_provider,
        model=args.model, max_attempts=args.max_attempts, out_dir=args.out,
        resample_budget=args.resample_budget, feedback_budget=args.feedback_budget)


if __name__ == "__main__":
    main()
