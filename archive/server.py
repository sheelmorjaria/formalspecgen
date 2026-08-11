# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""FastAPI service: NL -> validated JML, with a bounded self-repair loop.

Endpoints:
  GET  /              -> static frontend (NL left / JML right)
  POST /generate_spec -> full pipeline: generate JML + `openjml -check` + repair loop
  POST /validate      -> `openjml -check` only on a provided stub (no LLM)

Run:  python server.py   (then open http://127.0.0.1:8000/)
"""
import asyncio
import os
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from typing import List, Optional

from pipeline import orchestrator, jml_io
from pipeline.verify import verify, classify, has_dropped_vc
from pipeline.parse_check import parse_check
from pipeline.parse_vcs import parse_vcs
from pipeline.refine import refine
from pipeline.handoff import handoff
from pipeline.ide import apply_passes, route_backend, discover_passes, PASS_NAMES
from pipeline.jml_to_dafny import translate_and_verify, detect_boundary, UnsupportedBoundary
from pipeline.spec_lint import lint_spec
from pipeline.explain_vc import explain_vc
from pipeline.llm import suggest_loop_invariant, explain_vc_with_llm, _chat_fn
from pipeline.rac import collect_rac_evidence, collect_integration_evidence
from pipeline.tla_backend import generate_and_check as generate_and_check_tla
from pipeline.architecture import parse_architecture, lint_architecture, check_composition
from pipeline.system_design import design_system, scaffold_interfaces
from pipeline.adr import generate_adr
from pipeline.refactor_impact import analyze_refactor
from pipeline.rust_support import (draft_rust, lint_rust, check_rust_syntax, verify_prusti,
                                   apply_rust_passes, RUST_PASS_NAMES)
from pipeline.elicit import extract_ambiguities, augment_spec
from pipeline.domain_generator import elicit_domain_questions, compile_domain_spec
from pipeline.scaffold_domain import scaffold_sources, registration_lines
from pipeline.assurance import assurance_verdict, gate_plan, parse_assurance_level
from pipeline.implementation import synthesize_implementation
from pipeline.kani import verify_kani
from pipeline.c_support import draft_acsl, verify_framac

PROTOCOL_VERSION = 2
DOMAIN_GENERATION_PROTOCOL_VERSION = 2

BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))

app = FastAPI(title="formalspecgen", version="0.1.0")
app.mount("/static", StaticFiles(directory=BUNDLE_ROOT / "static"), name="static")
_run_blocking = asyncio.to_thread


async def _run_with_events(websocket: WebSocket, func, *args, **kwargs):
    """Run blocking pipeline work in a thread and stream its callback events."""
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()

    def publish(event):
        loop.call_soon_threadsafe(queue.put_nowait, event)

    kwargs["on_event"] = publish
    task = asyncio.create_task(asyncio.to_thread(func, *args, **kwargs))
    while not task.done():
        try:
            event = await asyncio.wait_for(queue.get(), timeout=0.25)
            await websocket.send_json(event)
        except asyncio.TimeoutError:
            pass
    while not queue.empty():
        await websocket.send_json(queue.get_nowait())
    return await task


def _verify_source(code, mode, on_event=None):
    """Worker-thread adapter for checking or deductively verifying editor text."""
    publish = on_event or (lambda _event: None)
    publish({"type": "progress", "stage": mode,
             "message": "Running OpenJML " + ("ESC verification" if mode == "esc" else "checks")})
    cname = jml_io.class_name(code) or "Draft"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / f"{cname}.java"
        path.write_text(code, encoding="utf-8")
        exit_code, output = verify(path, mode=mode)
    failures = parse_vcs(output) if mode == "esc" else parse_check(output)
    if exit_code != 0 and not failures and output.strip():
        from pipeline.schemas import VC
        failures = [VC(file=f"{cname}.java", line=0, category="error",
                       detail=output.strip()[:1000], raw=output.strip()[:1000])]
    for vc in failures:
        explanation = explain_vc(vc.category, vc.detail or vc.raw)
        publish({"type": "vc_failure", "file": vc.file, "line": vc.line,
                 "category": vc.category, "method": vc.method,
                 "declaration": vc.decl, "message": vc.detail or vc.raw, **explanation})
    status = classify(exit_code)
    if mode == "esc" and status == "VERIFIED" and has_dropped_vc(output):
        status = "VACUOUS_VERIFIED"
    publish({"type": "verified" if status == "VERIFIED" else "complete",
             "status": status, "exit_code": exit_code, "failures": len(failures),
             "raw": output.strip()})
    return status


def _verify_source_auto(code, on_event=None):
    """Try OpenJML first, then route only recognized encoding boundaries to Dafny."""
    publish = on_event or (lambda _event: None)
    publish({"type": "progress", "stage": "esc", "message": "Trying OpenJML/Z3 first"})
    cname = jml_io.class_name(code) or "Draft"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / f"{cname}.java"
        path.write_text(code, encoding="utf-8")
        exit_code, output = verify(path, mode="esc")
    status = classify(exit_code)
    if status == "VERIFIED" and has_dropped_vc(output):
        status = "VACUOUS_VERIFIED"
    if status == "VERIFIED":
        publish({"type": "verified", "status": status, "backend": "jml",
                 "exit_code": exit_code, "failures": 0, "raw": output.strip()})
        return status

    boundary = detect_boundary(code)
    if boundary is None:
        failures = parse_vcs(output)
        for vc in failures:
            explanation = explain_vc(vc.category, vc.detail or vc.raw)
            publish({"type": "vc_failure", "file": vc.file, "line": vc.line,
                     "category": vc.category, "method": vc.method,
                     "declaration": vc.decl, "message": vc.detail or vc.raw, **explanation})
        publish({"type": "complete", "status": status, "backend": "jml",
                 "exit_code": exit_code, "failures": len(failures), "raw": output.strip()})
        return status

    publish({"type": "backend_route", "backend": "dafny", "executable": True,
             "reasons": [f"recognized {boundary} encoding boundary"],
             "message": "OpenJML did not verify; routing the recognized boundary to Dafny"})
    try:
        result = translate_and_verify(code)
    except UnsupportedBoundary as exc:
        publish({"type": "complete", "status": status, "backend": "jml",
                 "exit_code": exit_code, "failures": 0, "raw": output.strip(),
                 "message": f"Dafny boundary lowering rejected this shape: {exc}"})
        return status
    publish({"type": "dafny_result", "status": result.status,
             "exit_code": result.exit_code, "output": result.output,
             "boundary": result.translation.boundary,
             "code": result.translation.dafny_code, "rewrites": result.translation.rewrites})
    return result.status


@app.websocket("/ws/verify")
async def verify_socket(websocket: WebSocket):
    """Stateful IDE protocol for drafting, checking, and ESC verification."""
    await websocket.accept()
    session = {}
    try:
        while True:
            payload = await websocket.receive_json()
            action = payload.get("action")
            if action == "protocol_info":
                await websocket.send_json({
                    "type": "protocol_info",
                    "protocol_version": PROTOCOL_VERSION,
                    "capabilities": ["domain_generation", "requirement_elicitation",
                                     "native_implementation", "bounded_architecture"],
                })
            elif action == "elicit_ambiguities":
                nl = str(payload.get("nl_text", "")).strip()
                if not nl:
                    await websocket.send_json({"type": "error", "message": "nl_text is required"})
                    continue
                provider = payload.get("provider") or "glm"
                await websocket.send_json({"type": "progress", "stage": "elicitation",
                                           "message": "Analyzing proof-relevant ambiguities"})
                questions, model, usage = await asyncio.to_thread(
                    extract_ambiguities, nl, _chat_fn(provider), payload.get("model"))
                session["elicitation"] = {"nl_text": nl, "questions": questions}
                await websocket.send_json({"type": "ambiguities", "questions": questions,
                                           "model": model, "usage": usage})
            elif action == "elicit_domain_questions":
                idea = str(payload.get("idea", "")).strip()
                await websocket.send_json({"type": "progress", "stage": "domain_elicitation",
                                           "message": "Clarifying the bounded domain model"})
                questions, model, usage = await asyncio.to_thread(
                    elicit_domain_questions, idea, _chat_fn(payload.get("provider") or "glm"),
                    payload.get("model"))
                await websocket.send_json({"type": "domain_questions", "questions": questions,
                                           "model": model, "usage": usage})
            elif action == "compile_domain_spec":
                await websocket.send_json({"type": "progress", "stage": "domain_compilation",
                                           "message": "Validating domain JSON and rendering YAML"})
                spec, yaml_text, model, usage = await asyncio.to_thread(
                    compile_domain_spec, str(payload.get("idea", "")),
                    payload.get("questions") or [], payload.get("answers") or [],
                    _chat_fn(payload.get("provider") or "glm"), payload.get("model"))
                await websocket.send_json({"type": "domain_spec_result", "status": "VALIDATED",
                                           "spec": spec.model_dump(mode="json"),
                                           "yaml": yaml_text, "model": model, "usage": usage,
                                           "files": scaffold_sources(spec),
                                           "registration": registration_lines(spec),
                                           "trust": "SCAFFOLD_REVIEW_REQUIRED"})
            elif action == "augment_requirements":
                nl = str(payload.get("nl_text", "")).strip()
                questions = payload.get("questions") or []
                enriched = augment_spec(nl, questions, payload.get("answers") or [])
                session["enriched_nl"] = enriched
                await websocket.send_json({"type": "requirements_augmented",
                                           "enriched_nl": enriched})
            elif action == "draft_spec":
                nl = str(payload.get("nl_text", "")).strip()
                if not nl:
                    await websocket.send_json({"type": "error", "message": "nl_text is required"})
                    continue
                await _run_with_events(
                    websocket, orchestrator.run, nl,
                    provider=payload.get("provider") or "glm",
                    fallback_provider=payload.get("fallback_provider"),
                    max_attempts=payload.get("max_attempts"),
                    workspace_files=payload.get("workspace_files") or {})
            elif action == "draft_rust":
                nl = str(payload.get("nl_text", "")).strip()
                if not nl:
                    await websocket.send_json({"type": "error", "message": "nl_text is required"})
                    continue
                await websocket.send_json({"type": "progress", "stage": "rust_draft",
                                           "message": "Drafting an experimental Prusti contract scaffold"})
                result = await asyncio.to_thread(draft_rust, nl, payload.get("provider") or "glm")
                warnings = result.pop("warnings", [])
                warnings.extend({"code": vc.get("category", "PrustiVerification"),
                                 "severity": "error", "line": vc.get("line", 1),
                                 "message": vc.get("detail") or vc.get("raw", "Prusti VC failed"),
                                 "source": "Prusti"}
                                for vc in (result.get("proof") or {}).get("vcs", []))
                await websocket.send_json({"type": "rust_draft_result", **result,
                                           "rust_warnings": warnings})
            elif action == "verify":
                code = str(payload.get("code", "")).strip()
                if not code:
                    await websocket.send_json({"type": "error", "message": "code is required"})
                    continue
                requested_mode = payload.get("mode")
                if requested_mode == "auto":
                    await _run_with_events(websocket, _verify_source_auto, code)
                else:
                    mode = "esc" if requested_mode == "esc" else "check"
                    await _run_with_events(websocket, _verify_source, code, mode)
            elif action == "postprocess_preview":
                code = str(payload.get("code", ""))
                selected = payload.get("passes")
                report = await asyncio.to_thread(apply_passes, code, selected)
                await websocket.send_json({"type": "postprocess_result", **report})
            elif action == "route_backend":
                await websocket.send_json({"type": "backend_route",
                                           "terminal": True,
                                           **route_backend(str(payload.get("code", "")))})
            elif action == "refine":
                code = str(payload.get("code", ""))
                instruction = str(payload.get("instruction", "")).strip()
                if not code.strip() or not instruction:
                    await websocket.send_json({"type": "error",
                                               "message": "code and instruction are required"})
                    continue
                await websocket.send_json({"type": "progress", "stage": "refine",
                                           "message": "Drafting a clause-aware refinement"})
                result = await asyncio.to_thread(
                    refine, code, instruction, payload.get("locked_clauses") or [], payload.get("nl"),
                    None, payload.get("provider") or "glm")
                await websocket.send_json({"type": "refine_result", **asdict(result)})
            elif action == "translate_dafny":
                code = str(payload.get("code", ""))
                await websocket.send_json({"type": "progress", "stage": "dafny_translate",
                                           "message": "Lowering a recognized boundary to Dafny"})
                try:
                    result = await asyncio.to_thread(translate_and_verify, code)
                    await websocket.send_json({
                        "type": "dafny_result", "status": result.status,
                        "exit_code": result.exit_code, "output": result.output,
                        "boundary": result.translation.boundary,
                        "code": result.translation.dafny_code,
                        "rewrites": result.translation.rewrites,
                    })
                except UnsupportedBoundary as exc:
                    await websocket.send_json({"type": "dafny_result",
                                               "status": "UNSUPPORTED_BOUNDARY",
                                               "message": str(exc), "code": "", "rewrites": []})
            elif action == "capabilities":
                from pipeline.domains.registry import PLUGINS
                await websocket.send_json({"type": "capabilities",
                                           "protocol_version": PROTOCOL_VERSION,
                                           "domain_generation_protocol_version": DOMAIN_GENERATION_PROTOCOL_VERSION,
                                           "postprocessor_passes": PASS_NAMES,
                                           "rust_postprocessor_passes": RUST_PASS_NAMES,
                                           "tla_domains": [plugin.name for plugin in PLUGINS],
                                           "assurance_profiles": ["critical", "standard", "lightweight"],
                                           "boundary_translator": ["heap_snapshot", "permutation_multiset", "recursive_helper"],
                                           "backends": {"jml": True, "dafny_targeted": True,
                                                        "tla_bounded": True, "rust_syntax": True,
                                                        "prusti": "bootstrapped_on_demand"},
                                           "features": ["limitation_retrieval", "spec_lint", "vc_explanations",
                                                        "interactive_requirement_elicitation",
                                                        "domain_plugin_generation",
                                                        "llm_vc_hover", "invariant_suggestions", "rac_evidence", "pass_discovery",
                                                        "structured_handoff", "architecture_wizard", "solid_lint",
                                                        "composition_verification", "adr_generation",
                                                        "architecture_rac", "safe_refactoring", "stride_threat_model",
                                                        "experimental_rust_drafting", "rust_lint",
                                                        "typed_tla_ir", "deterministic_tla_renderer"]})
            elif action == "assurance_plan":
                level = parse_assurance_level(payload.get("assurance_level"))
                await websocket.send_json({
                    "type": "assurance_plan", "assurance_level": level.value,
                    "gates": [item.model_dump() for item in gate_plan(level)]})
            elif action == "assurance_verdict":
                result = assurance_verdict(
                    payload.get("assurance_level"), payload.get("gate_statuses") or {})
                await websocket.send_json({"type": "assurance_verdict", **result})
            elif action == "lint":
                await websocket.send_json({"type": "lint_result",
                                           "warnings": lint_spec(str(payload.get("code", "")))})
            elif action == "rust_lint":
                await websocket.send_json({"type": "rust_lint_result",
                                           "warnings": lint_rust(str(payload.get("code", "")))})
            elif action == "rust_postprocess_preview":
                result = await asyncio.to_thread(
                    apply_rust_passes, str(payload.get("code", "")), payload.get("passes"))
                await websocket.send_json({"type": "rust_postprocess_result", **result})
            elif action == "rust_check":
                result = await asyncio.to_thread(check_rust_syntax, str(payload.get("code", "")))
                await websocket.send_json({"type": "rust_check_result", **result,
                                           "verification_status": "NOT_RUN"})
            elif action == "rust_verify":
                result = await asyncio.to_thread(verify_prusti, str(payload.get("code", "")))
                for vc in result.get("vcs", []):
                    explanation = explain_vc(vc["category"], vc.get("detail") or vc.get("raw", ""))
                    await websocket.send_json({"type": "vc_failure", "backend": "prusti", **vc,
                                               "message": vc.get("detail") or vc.get("raw", ""),
                                               **explanation})
                await websocket.send_json({"type": "rust_verify_result", **result,
                                           "verification_status": result["status"]})
            elif action == "kani_verify":
                result = await asyncio.to_thread(verify_kani, str(payload.get("code", "")))
                await websocket.send_json({"type": "kani_result", **result})
            elif action == "draft_acsl":
                result = await asyncio.to_thread(
                    draft_acsl, str(payload.get("nl_text", "")), payload.get("provider") or "glm")
                await websocket.send_json({"type": "acsl_draft_result", **result})
            elif action == "framac_verify":
                result = await asyncio.to_thread(verify_framac, str(payload.get("code", "")))
                await websocket.send_json({"type": "framac_result", **result})
            elif action == "suggest_invariant":
                code = str(payload.get("code", ""))
                loop_line = str(payload.get("loop_line", ""))
                provider = payload.get("provider") or "glm"
                suggestion, model, _usage = await asyncio.to_thread(
                    suggest_loop_invariant, code, loop_line, None, 0.0, _chat_fn(provider))
                await websocket.send_json({"type": "invariant_suggestion",
                                           "suggestion": suggestion, "model": model})
            elif action == "rac_evidence":
                await websocket.send_json({"type": "progress", "stage": "rac",
                                           "message": "Compiling RAC instrumentation and generating focused tests"})
                evidence = await asyncio.to_thread(
                    collect_rac_evidence, str(payload.get("code", "")),
                    str(payload.get("diagnostics", "")), payload.get("provider") or "glm")
                await websocket.send_json({"type": "rac_result", **evidence})
            elif action == "discover_passes":
                await websocket.send_json({"type": "pass_suggestions",
                                           "suggestions": discover_passes(str(payload.get("code", "")))})
            elif action == "translate_tla":
                await websocket.send_json({"type": "progress", "stage": "tla",
                                           "message": "Rendering a validated bounded concurrency IR for TLC"})
                result = await asyncio.to_thread(
                    generate_and_check_tla, str(payload.get("code", "")),
                    payload.get("provider") or "glm", 2,
                    str(payload.get("clarifications", "")), payload.get("abstraction"))
                await websocket.send_json({"type": "tla_result", **result})
            elif action in {"implementation_synthesize", "implementation_handoff"}:
                code = str(payload.get("code", ""))
                if not code.strip():
                    await websocket.send_json({"type": "error", "message": "trusted JML scaffold is required"})
                    continue
                await websocket.send_json({"type": "progress", "stage": "implementation",
                                           "message": "Generating and deductively verifying the implementation"})
                if action == "implementation_handoff":
                    result = await asyncio.to_thread(
                        handoff, code, True, int(payload.get("timeout", 600)),
                        payload.get("expected_passes") or [], payload.get("backend") or "jml")
                    verdict = result.get("dd_verdict") or {}
                    status = verdict.get("final_status") or (
                        "HANDOFF_READY" if result.get("ok") else "HANDOFF_FAILED")
                else:
                    result = await asyncio.to_thread(
                        synthesize_implementation, code, payload.get("provider") or "glm",
                        payload.get("model"), None, int(payload.get("max_attempts", 5)),
                        int(payload.get("resample_budget", 1)),
                        int(payload.get("feedback_budget", 4)),
                        payload.get("accepted_passes") or [])
                    status = result["final_status"]
                await websocket.send_json({"type": "implementation_result", **result,
                                           "status": status})
            elif action == "explain_vc":
                explanation, model, _usage = await asyncio.to_thread(
                    explain_vc_with_llm, str(payload.get("category", "VerificationCondition")),
                    str(payload.get("detail", "")), str(payload.get("source_line", "")),
                    None, _chat_fn(payload.get("provider") or "glm"))
                await websocket.send_json({"type": "llm_vc_explanation",
                                           "explanation": explanation, "model": model})
            elif action == "architecture_design":
                await websocket.send_json({"type": "progress", "stage": "architecture",
                                           "message": "Drafting and model-checking the system architecture"})
                result = await asyncio.to_thread(
                    design_system, str(payload.get("requirement", "")),
                    payload.get("provider") or "glm", int(payload.get("max_attempts", 3)))
                if result.get("architecture"):
                    session["architecture"] = result["architecture"]
                await websocket.send_json({"type": "architecture_result", **result})
            elif action == "architecture_lint":
                value = payload.get("architecture") or session.get("architecture")
                if not value:
                    await websocket.send_json({"type": "error", "message": "no architecture is available"})
                    continue
                architecture = parse_architecture(value)
                await websocket.send_json({"type": "architecture_lint_result",
                                           "architecture": architecture.to_dict(),
                                           "warnings": lint_architecture(
                                               architecture, payload.get("source_files") or {})})
            elif action == "architecture_scaffold":
                value = payload.get("architecture") or session.get("architecture")
                if not value:
                    await websocket.send_json({"type": "error", "message": "no architecture is available"})
                    continue
                result = await asyncio.to_thread(scaffold_interfaces, value)
                session["scaffold"] = result
                await websocket.send_json({"type": "architecture_scaffold_result", **result})
            elif action == "composition_check":
                value = payload.get("architecture") or session.get("architecture")
                if not value:
                    await websocket.send_json({"type": "error", "message": "no architecture is available"})
                    continue
                warnings = check_composition(parse_architecture(value))
                await websocket.send_json({"type": "composition_result",
                                           "status": "VERIFIED" if not warnings else "COMPOSITION_FAILED",
                                           "warnings": warnings})
            elif action == "architecture_adr":
                value = payload.get("architecture") or session.get("architecture")
                if not value:
                    await websocket.send_json({"type": "error", "message": "no architecture is available"})
                    continue
                markdown = generate_adr(value, payload.get("verification") or {},
                                        int(payload.get("number", 1)))
                await websocket.send_json({"type": "architecture_adr_result",
                                           "status": "GENERATED", "markdown": markdown})
            elif action == "architecture_rac":
                files = payload.get("files") or (session.get("scaffold") or {}).get("files")
                if not files:
                    await websocket.send_json({"type": "error", "message": "no scaffold files are available"})
                    continue
                await websocket.send_json({"type": "progress", "stage": "architecture_rac",
                                           "message": "Running RAC orchestrator integration tests"})
                result = await asyncio.to_thread(
                    collect_integration_evidence, files, payload.get("provider") or "glm")
                await websocket.send_json({"type": "architecture_rac_result", **result})
            elif action == "refactor_impact":
                value = payload.get("architecture") or session.get("architecture")
                if not value:
                    await websocket.send_json({"type": "error", "message": "no architecture is available"})
                    continue
                result = await asyncio.to_thread(
                    analyze_refactor, value, payload.get("before_files") or {},
                    payload.get("after_files") or {})
                await websocket.send_json({"type": "refactor_impact_result", **result})
            else:
                await websocket.send_json({"type": "error", "message": f"unknown action: {action}"})
    except WebSocketDisconnect:
        return
    except Exception as exc:  # noqa: BLE001 - protocol errors must reach the IDE
        await websocket.send_json({"type": "error", "message": str(exc)})


class NLIn(BaseModel):
    nl: str
    provider: Optional[str] = "glm"
    fallback_provider: Optional[str] = None


class StubIn(BaseModel):
    java_stub: str


@app.get("/")
async def index():
    return FileResponse(BUNDLE_ROOT / "static" / "index.html")


@app.post("/generate_spec")
async def generate_spec(body: NLIn):
    if not body.nl.strip():
        return JSONResponse(status_code=400, content={"error": "nl is empty"})
    try:
        res = await _run_blocking(
            orchestrator.run, body.nl, provider=body.provider or "glm",
            fallback_provider=body.fallback_provider)
    except Exception as e:  # noqa: BLE001 - surface any failure to the UI
        return JSONResponse(status_code=500, content={"error": str(e)})

    stub_text = (Path(res.stub_path).read_text(encoding="utf-8") if res.stub_path and
                 Path(res.stub_path).exists() else "")
    return {
        "status": res.final_status,
        "stop_reason": res.stop_reason,
        "jml": jml_io.extract_jml(stub_text),
        "java_stub": stub_text,
        "assumptions": res.assumptions,
        "missing_info": res.missing_info,
        "attempts": [
            {"n": a.n, "status": a.status, "exit_code": a.exit_code,
             "errors": [v.detail or v.raw for v in a.vcs], "note": a.note}
            for a in res.attempts
        ],
        "model": res.model,
        "duration_s": round(res.duration_s, 1),
        "tokens": res.tokens,
    }


@app.post("/validate")
async def validate(body: StubIn):
    """Run `openjml -check` on an edited stub (no LLM). Used by the Validate button."""
    if not body.java_stub.strip():
        return JSONResponse(status_code=400, content={"error": "java_stub is empty"})
    code_exit, text = await _run_blocking(_validate_stub, body.java_stub)
    vcs = parse_check(text) if code_exit != 0 else []
    return {
        "status": classify(code_exit),
        "exit_code": code_exit,
        "errors": [v.detail or v.raw for v in vcs],
        "raw": text.strip(),
    }


class RefineIn(BaseModel):
    current_stub: str
    instruction: str
    locked_clauses: List[str] = []
    nl: Optional[str] = None


@app.post("/refine")
async def refine_endpoint(body: RefineIn):
    """Targeted, no-clobber refinement: update the stub per the human's instruction,
    return a clause-level diff and any conflicts (locked clauses the model altered).
    The stub is only replaced when the human accepts; this never silently clobbers edits."""
    if not body.current_stub.strip() or not body.instruction.strip():
        return JSONResponse(status_code=400,
                            content={"error": "current_stub and instruction are required"})
    try:
        r = await _run_blocking(
            refine, body.current_stub, body.instruction, body.locked_clauses, body.nl)
    except Exception as e:  # noqa: BLE001 - surface any failure to the UI
        return JSONResponse(status_code=500, content={"error": str(e)})
    return {
        "new_stub": r.new_stub,
        "jml": jml_io.extract_jml(r.new_stub),
        "check_ok": r.check_ok,
        "check_errors": r.check_errors[:8],
        "diff": r.diff,
        "conflicts": r.conflicts,
        "assumptions": r.assumptions,
        "missing_info": r.missing_info,
        "model": r.model,
        "error": r.error,
        "duration_s": r.duration_s,
    }


class HandoffIn(BaseModel):
    java_stub: str
    run: bool = False
    expected_passes: Optional[List[str]] = None
    backend: Optional[str] = None


class ImplementationIn(BaseModel):
    java_stub: str
    provider: str = "glm"
    model: Optional[str] = None
    max_attempts: int = 5
    resample_budget: int = 1
    feedback_budget: int = 4
    accepted_passes: List[str] = []


@app.post("/implement")
async def implementation_endpoint(body: ImplementationIn):
    """Natively synthesize Java bodies and judge them with javac then OpenJML ESC."""
    if not body.java_stub.strip():
        return JSONResponse(status_code=400, content={"error": "java_stub is empty"})
    try:
        return await _run_blocking(
            synthesize_implementation, body.java_stub, body.provider, body.model, None,
            body.max_attempts, body.resample_budget, body.feedback_budget,
            body.accepted_passes)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"error": str(exc)})


@app.post("/handoff")
async def handoff_endpoint(body: HandoffIn):
    """Hand the validated JML stub to formalspecDD (write DD-format file + emit command).
    With run=true, invoke DD's orchestrator and return its verdict (slow: LLM + `openjml -esc`).
    This closes the NL -> spec -> verified-Java loop across the two projects."""
    if not body.java_stub.strip():
        return JSONResponse(status_code=400, content={"error": "java_stub is empty"})
    try:
        expected = body.expected_passes
        if expected is None:
            expected = [item["name"] for item in discover_passes(body.java_stub)]
        backend = body.backend or route_backend(body.java_stub)["backend"]
        return await _run_blocking(
            handoff, body.java_stub, run_dd=body.run,
            expected_passes=expected, backend=backend)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"error": str(e)})


def _validate_stub(stub: str) -> tuple[int, str]:
    """Keep the temporary source alive for the complete blocking OpenJML invocation."""
    cname = jml_io.class_name(stub) or "Draft"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / f"{cname}.java"
        path.write_text(stub, encoding="utf-8")
        return verify(path, mode="check")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
