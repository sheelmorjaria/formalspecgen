# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed Rust/Prusti and C/ACSL implementation synthesis loops."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

from . import config, strategy
from .c_support import apply_c_passes, lint_acsl
from .lifecycle import sha256_text
from .llm import LLMError, _chat_fn
from .polyglot_runtime import collect_polyglot_runtime_evidence
from .rust_support import apply_rust_passes, lint_rust
from .schemas import VC
from .verify_c import verify_c
from .verify_rust import verify_rust

_RUST_CONTRACT = re.compile(r"#\[(?:requires|ensures|pure|trusted|terminates)[\s\S]*?\]")
_RUST_SIGNATURE = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:async\s+)?fn\s+"
    r"[A-Za-z_]\w*\s*(?:<[^>{;]*>)?\s*\([^;{}]*\)\s*(?:->\s*[^;{]+)?")
_RUST_TRAIT = re.compile(r"(?m)^\s*(?:pub\s+)?trait\s+[A-Za-z_]\w*(?:<[^>{]*>)?[^\{]*\{")
_ACSL_CONTRACT = re.compile(r"/\*@(?:.|\n)*?\*/", re.MULTILINE)
_C_SIGNATURE = re.compile(
    r"(?m)^\s*(?!if\b|for\b|while\b|switch\b)(?:[A-Za-z_]\w*\s+|\*\s*)+"
    r"[A-Za-z_]\w*\s*\([^;{}]*\)\s*(?=\{|;)")
_SOURCE_FENCE = {
    "rust": re.compile(r"```rust\s*\n(.*?)```", re.DOTALL | re.IGNORECASE),
    "c": re.compile(r"```c\s*\n(.*?)```", re.DOTALL | re.IGNORECASE),
}

RUST_IMPLEMENT_SYSTEM = r"""You implement a complete Rust source scaffold verified by Prusti.
Preserve every trait, function signature, and #[requires]/#[ensures]/#[pure] attribute exactly.
Change method/function bodies only. Output exactly one complete Rust file in a ```rust block.
Do not use unsafe, raw pointers, unwrap, expect, panic, todo, or unimplemented. Respect ownership
and borrowing. Add body_invariant! facts when loops require induction; never weaken a contract."""

C_IMPLEMENT_SYSTEM = r"""You implement a complete C11 source scaffold verified by Frama-C WP.
Preserve every function signature and every ACSL contract exactly. Change function bodies only.
Output exactly one complete C file in a ```c block. Do not use allocation, recursion, unchecked
pointer arithmetic, unsafe library calls, compiler extensions, or concurrency. Add ACSL loop
invariant, loop assigns, and loop variant annotations when loops require induction. Never weaken a
contract or add assumptions."""


def _normalized(values) -> list[str]:
    return sorted(re.sub(r"\s+", " ", value.group(0)).strip() for value in values)


def rust_trusted_surface(code: str) -> dict:
    return {"traits": _normalized(_RUST_TRAIT.finditer(code)),
            "signatures": _normalized(_RUST_SIGNATURE.finditer(code)),
            "contracts": _normalized(_RUST_CONTRACT.finditer(code))}


def _c_function_contracts(code: str) -> list[str]:
    """Lock ACSL blocks attached to APIs, not loop invariants inside implementations."""
    contracts = []
    blocks = list(_ACSL_CONTRACT.finditer(code))
    for signature in _C_SIGNATURE.finditer(code):
        preceding = [block for block in blocks if block.end() <= signature.start()]
        if not preceding:
            continue
        block = preceding[-1]
        if not code[block.end():signature.start()].strip():
            contracts.append(re.sub(r"\s+", " ", block.group(0)).strip())
    return sorted(contracts)


def c_trusted_surface(code: str) -> dict:
    return {"signatures": _normalized(_C_SIGNATURE.finditer(code)),
            "contracts": _c_function_contracts(code)}


def trusted_surface_matches(stub: str, candidate: str, language: str) -> tuple[bool, dict]:
    extractor = rust_trusted_surface if language == "rust" else c_trusted_surface
    expected, actual = extractor(stub), extractor(candidate)
    differences = {key: {"expected": expected[key], "actual": actual[key]}
                   for key in expected if expected[key] != actual[key]}
    return not differences, differences


def _generate(stub: str, language: str, provider: str, model: str | None,
              previous: str | None = None, diagnostics: str = ""):
    system = RUST_IMPLEMENT_SYSTEM if language == "rust" else C_IMPLEMENT_SYSTEM
    prompt = f"Trusted {language} scaffold:\n```{language}\n{stub}\n```\n"
    if previous is None:
        prompt += "Implement every body and return the complete source file."
    else:
        prompt += (f"Previous candidate:\n```{language}\n{previous}\n```\n"
                   f"Verifier diagnostics:\n```text\n{diagnostics[-12000:]}\n```\n"
                   "Repair the implementation and return the complete source file.")
    return _chat_fn(provider)([{"role": "system", "content": system},
                               {"role": "user", "content": prompt}], model, 0.2)


def _source_from_response(response: str, language: str) -> str:
    match = _SOURCE_FENCE[language].search(response)
    return match.group(1).strip() + "\n" if match else response.strip() + "\n"


def _shared_vcs(rows: list[dict] | None) -> list[VC]:
    fields = {"file", "line", "category", "method", "decl", "detail", "raw"}
    return [VC(**{key: value for key, value in row.items() if key in fields})
            for row in (rows or [])]


def synthesize_polyglot_implementation(
        stub: str, language: str, provider: str = "glm", model: str | None = None,
        out_dir: str | Path | None = None, max_attempts: int = 5,
        resample_budget: int = 1, feedback_budget: int = 4,
        accepted_passes: list[str] | None = None, candidate: str | None = None,
        on_event: Callable[[dict], None] | None = None,
        verification_mode: str = "esc", runtime_gate: bool = False,
        runtime_test_code: str | None = None) -> dict:
    """Synthesize bodies while treating contracts and APIs as immutable trusted input."""
    if language not in {"rust", "c"}:
        raise ValueError("language must be rust or c")
    if verification_mode not in {"esc", "check"}:
        raise ValueError("verification_mode must be esc or check")
    surface = rust_trusted_surface(stub) if language == "rust" else c_trusted_surface(stub)
    if not surface["signatures"] or not surface["contracts"]:
        return {"final_status": "INVALID_STUB", "claim": "NO_PROOF", "attempts": [],
                "stop_reason": f"{language} scaffold has no recognized contract/signature"}

    name = "RustImplementation" if language == "rust" else "c-implementation"
    suffix = ".rs" if language == "rust" else ".c"
    root = Path(out_dir) if out_dir else config.ROOT / "runs" / name / time.strftime("%Y%m%d-%H%M%S-impl")
    root.mkdir(parents=True, exist_ok=True)
    publish = on_event or (lambda _event: None)
    attempts: list[dict] = []
    history: list[tuple[str, list, str]] = []
    samples = feedback = 0
    final_code = ""
    stop_reason = ""

    while True:
        passed = bool(attempts) and attempts[-1]["status"] in {"VERIFIED", "STATIC_CHECKED"}
        decision = strategy.decide(history, passed, samples, feedback, max_attempts,
                                   resample_budget, feedback_budget)
        if decision.action == "stop":
            stop_reason = decision.reason
            break
        number = len(attempts) + 1
        attempt_dir = root / f"attempt{number}"
        attempt_dir.mkdir(exist_ok=True)
        publish({"type": "progress", "stage": f"{language}_implementation_{decision.action}",
                 "attempt": number, "message": decision.reason})
        try:
            if candidate is not None and not attempts:
                generated, used_model, usage = candidate, model or "fixture", {}
                samples += 1
            elif decision.action == "sample":
                raw, used_model, usage = _generate(stub, language, provider, model)
                generated = _source_from_response(raw, language)
                samples += 1
            else:
                raw, used_model, usage = _generate(stub, language, provider, model,
                                                   history[-1][0], history[-1][2])
                generated = _source_from_response(raw, language)
                feedback += 1
        except LLMError as exc:
            attempts.append({"attempt": number, "status": "API_ERROR", "exit_code": -2,
                             "message": str(exc), "vcs": []})
            stop_reason = f"LLMError [{exc.code}]"
            break

        if not generated.strip():
            attempts.append({"attempt": number, "status": "GEN_EMPTY", "exit_code": -3,
                             "model": used_model, "vcs": []})
            history.append((generated, [], "empty generation"))
            continue

        trusted, differences = trusted_surface_matches(stub, generated, language)
        if not trusted:
            attempts.append({"attempt": number, "status": "TRUST_BOUNDARY_VIOLATION",
                             "exit_code": -4, "model": used_model,
                             "surface_diff": differences, "vcs": []})
            stop_reason = "generated candidate modified a trusted contract or API"
            break

        transformed = generated
        postprocess = None
        if accepted_passes:
            postprocess = (apply_rust_passes(generated, accepted_passes) if language == "rust"
                           else apply_c_passes(generated, accepted_passes))
            postprocess["accepted"] = True
            transformed = postprocess["code"]

        findings = lint_rust(transformed) if language == "rust" else lint_acsl(transformed)
        blockers = [item for item in findings if item.get("severity") == "error"]
        runtime = None
        if not blockers and runtime_gate:
            runtime = collect_polyglot_runtime_evidence(
                transformed, language, provider, test_code=runtime_test_code)
        if blockers:
            verification = {"status": "RUST_LINT_FAILED" if language == "rust" else "ACSL_LINT_FAILED",
                            "exit_code": 2, "warnings": findings, "vcs": []}
        elif runtime and runtime["status"] != "NO_RUNTIME_FAILURE_FOUND":
            verification = {"status": runtime["status"],
                            "exit_code": runtime.get("exit_code", 1),
                            "output": runtime.get("log", ""), "vcs": []}
        elif language == "rust":
            verification = verify_rust(transformed, mode=verification_mode, backend="prusti")
        else:
            verification = verify_c(transformed, mode=verification_mode)
        status = verification.get("status", "VERIFY_FAILED")
        if verification_mode == "check" and language == "rust" and status == "RUST_CHECKED":
            status = "STATIC_CHECKED"
        if verification_mode == "check" and language == "c" and status == "C_CHECKED":
            status = "STATIC_CHECKED"
        output = str(verification.get("output") or verification.get("message") or
                     json.dumps(verification.get("warnings", [])))
        source = attempt_dir / f"candidate{suffix}"
        source.write_text(transformed, encoding="utf-8")
        (attempt_dir / "verifier.log").write_text(output, encoding="utf-8")
        attempt = {"attempt": number, "status": status,
                   "exit_code": verification.get("exit_code", 1), "model": used_model,
                   "tokens": usage, "candidate_hash": sha256_text(transformed),
                   "contract_hash": sha256_text(json.dumps(surface, sort_keys=True)),
                   "vcs": verification.get("vcs", []), "warnings": findings,
                   "accepted_passes": accepted_passes or [], "postprocess": postprocess,
                   "runtime_evidence": runtime}
        attempts.append(attempt)
        history.append((transformed, _shared_vcs(verification.get("vcs")), output))
        final_code = transformed
        publish({"type": "implementation_attempt", **attempt})

    final_status = attempts[-1]["status"] if attempts else "NO_ATTEMPT"
    claim = ("DEDUCTIVE_PROOF" if final_status == "VERIFIED" and verification_mode == "esc"
             else "STATIC_CHECK" if final_status == "STATIC_CHECKED" else "NO_PROOF")
    result = {"final_status": final_status, "stop_reason": stop_reason,
              "language": language, "attempts": attempts, "implementation_code": final_code,
              "implementation_path": str(root / f"implementation{suffix}") if final_code else "",
              "verification_backend": "prusti" if language == "rust" else "frama-c-wp",
              "verification_mode": verification_mode, "claim": claim,
              "trusted_contract_hash": sha256_text(json.dumps(surface, sort_keys=True)),
              "native_synthesis": True, "external_handoff_used": False}
    if attempts:
        result["runtime_evidence"] = attempts[-1].get("runtime_evidence")
    if final_code:
        (root / f"implementation{suffix}").write_text(final_code, encoding="utf-8")
    (root / "verdict.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
