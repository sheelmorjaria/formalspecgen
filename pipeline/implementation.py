# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Native trusted-JML -> Java implementation -> deductive verification loop."""
from __future__ import annotations

import json
import argparse
import re
import subprocess
import tempfile
import time
from pathlib import Path

from . import config, jml_io, strategy
from .ide import apply_passes
from .lifecycle import failure_fingerprint, sha256_text
from .llm import LLMError, _chat_fn, strip_fence
from .parse_check import parse_check
from .parse_vcs import parse_vcs
from .verify import classify, has_dropped_vc, verify


IMPLEMENT_SYSTEM = """You are a formal-verification engineer using Java, JML, OpenJML 21, and Z3.
Implement every method body in the trusted JML-annotated Java scaffold.

Hard requirements:
- Do not modify, remove, reorder, or add JML clauses, fields, class names, or method signatures.
- Preserve package and import declarations.
- Output exactly one complete Java file in a ```java fenced block and no prose.
- Add loop_invariant and decreases annotations when loops require inductive proof.
- Never weaken a contract or add assumptions to make verification pass.
- Keep Java arithmetic within contract bounds and avoid hidden side effects.
"""

REPAIR_SYSTEM = IMPLEMENT_SYSTEM + """
Repair mode: preserve the trusted scaffold exactly and change implementation/proof annotations only.
Use the OpenJML diagnostics to repair the root cause. Do not suppress or delete obligations.

Diagnostic rules:
- InvariantExit means the candidate's state update can violate a class invariant. Inspect every
  field mentioned by the associated invariant and derive a guard that makes the update preserve it.
  Do not merely repeat a precondition about the field being assigned. For an invariant of the form
  !(A == value && B == value), assigning A = value requires establishing B != value first, and
  assigning B = value requires establishing A != value first.
- Postcondition means implement the promised state transition or returned field directly.
- ArithmeticOperationRange means use the existing trusted bounds; never add a new assumption.
- Return a materially changed candidate. Repeating the previous candidate cannot repair a VC.
"""

_METHOD = re.compile(
    r"(?m)^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?"
    r"[\w<>\[\], ?]+\s+\w+\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\{")
_FIELD = re.compile(
    r"(?m)^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?"
    r"[\w<>\[\], ?]+\s+\w+\s*(?:=[^;]*)?;")
_PROOF_ONLY = re.compile(r"^(?:loop_invariant|decreases|assert|assume)\b", re.I)


def _surface(code: str) -> dict:
    def normalized(matches):
        return sorted(re.sub(r"\s+", " ", match.group(0)).strip().rstrip("{").strip()
                      for match in matches)
    cname = jml_io.class_name(code)
    constructors = [] if not cname else normalized(re.finditer(
        rf"(?m)^\s*(?:public|protected|private)\s+{re.escape(cname)}\s*\([^;{{}}]*\)\s*{{", code))
    clauses = [clause for clause in jml_io.extract_clauses(code)
               if not _PROOF_ONLY.match(clause)]
    return {"class": cname, "methods": normalized(_METHOD.finditer(code)),
            "constructors": constructors,
            "fields": normalized(_FIELD.finditer(code)),
            "clauses": sorted(clauses)}


def trusted_surface_matches(stub: str, candidate: str) -> tuple[bool, dict]:
    expected, actual = _surface(stub), _surface(candidate)
    differences = {key: {"expected": expected[key], "actual": actual[key]}
                   for key in expected if expected[key] != actual[key]}
    return not differences, differences


def _chat_generate(stub: str, model: str | None, provider: str):
    return _chat_fn(provider)([
        {"role": "system", "content": IMPLEMENT_SYSTEM},
        {"role": "user", "content": "Trusted JML scaffold:\n```java\n" + stub +
         "\n```\nImplement and return the complete Java file."},
    ], model, 0.2)


def _chat_repair(stub: str, previous: str, diagnostics: str,
                 model: str | None, provider: str):
    return _chat_fn(provider)([
        {"role": "system", "content": REPAIR_SYSTEM},
        {"role": "user", "content": "Trusted JML scaffold:\n```java\n" + stub +
         "\n```\nPrevious candidate:\n```java\n" + previous +
         "\n```\nOpenJML diagnostics:\n```text\n" + diagnostics[-12000:] +
         "\n```\nReturn a corrected complete Java file."},
    ], model, 0.2)


def _javac(source: Path, timeout: int = 60) -> tuple[int, str]:
    source = source.resolve()
    try:
        process = subprocess.run([config.JAVAC, "-proc:none", str(source)],
            cwd=str(source.parent), capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout)
        return process.returncode, ((process.stdout or "") + (process.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"javac timed out after {timeout}s"
    except FileNotFoundError:
        return 127, f"javac not found: {config.JAVAC}"


def _tokens(usage: dict) -> dict:
    return {"input": usage.get("prompt_tokens", 0),
            "output": usage.get("completion_tokens", 0),
            "total": usage.get("total_tokens", 0)}


def synthesize_implementation(stub: str, provider: str = "glm", model: str | None = None,
                              out_dir: str | Path | None = None, max_attempts: int = 5,
                              resample_budget: int = 1, feedback_budget: int = 4,
                              accepted_passes: list[str] | None = None,
                              candidate: str | None = None, on_event=None,
                              verification_mode: str = "esc") -> dict:
    """Generate or verify an implementation locally; never delegates to formalspecDD."""
    if verification_mode not in {"esc", "check", "compile"}:
        raise ValueError("verification_mode must be esc, check, or compile")
    cname = jml_io.class_name(stub)
    if not cname:
        return {"final_status": "INVALID_STUB", "stop_reason": "no public class",
                "attempts": [], "claim": "NO_PROOF"}
    root = Path(out_dir) if out_dir else config.ROOT / "runs" / cname / time.strftime("%Y%m%d-%H%M%S-impl")
    root.mkdir(parents=True, exist_ok=True)
    publish = on_event or (lambda _event: None)
    attempts, history = [], []
    samples = feedback = 0
    total = {"input": 0, "output": 0, "total": 0}
    final_code = ""
    stop_reason = ""

    while True:
        verified = bool(attempts) and attempts[-1]["status"] in {
            "VERIFIED", "STATIC_CHECKED", "COMPILED"}
        decision = strategy.decide(history, verified, samples, feedback, max_attempts,
                                   resample_budget, feedback_budget)
        if decision.action == "stop":
            stop_reason = decision.reason
            break
        number = len(attempts) + 1
        attempt_dir = root / f"attempt{number}"
        attempt_dir.mkdir(exist_ok=True)
        publish({"type": "progress", "stage": "implementation_" + decision.action,
                 "attempt": number, "message": decision.reason})
        try:
            if candidate is not None and not attempts:
                generated, used_model, usage = candidate, model or "fixture", {}
                samples += 1
            elif decision.action == "sample":
                raw, used_model, usage = _chat_generate(stub, model, provider)
                generated = strip_fence(raw)
                samples += 1
            else:
                raw, used_model, usage = _chat_repair(
                    stub, history[-1][0], history[-1][2], model, provider)
                generated = strip_fence(raw)
                feedback += 1
        except LLMError as exc:
            attempts.append({"attempt": number, "status": "API_ERROR", "exit_code": -2,
                             "message": str(exc), "vcs": []})
            stop_reason = f"LLMError [{exc.code}]"
            break

        usage = _tokens(usage)
        for key in total:
            total[key] += usage[key]
        if not generated.strip():
            attempts.append({"attempt": number, "status": "GEN_EMPTY", "exit_code": -3,
                             "model": used_model, "tokens": usage, "vcs": []})
            history.append((generated, [], "empty generation"))
            continue

        trusted, differences = trusted_surface_matches(stub, generated)
        if not trusted:
            attempts.append({"attempt": number, "status": "TRUST_BOUNDARY_VIOLATION",
                             "exit_code": -4, "model": used_model, "tokens": usage,
                             "surface_diff": differences, "vcs": []})
            stop_reason = "generated candidate modified the trusted contract or Java API"
            break

        transformed = generated
        pass_report = None
        if accepted_passes:
            pass_report = apply_passes(generated, accepted_passes)
            pass_report["accepted"] = True
            transformed = pass_report["code"]
        source = attempt_dir / f"{cname}.java"
        source.write_text(transformed, encoding="utf-8")
        javac_exit, javac_text = _javac(source)
        (attempt_dir / "javac.log").write_text(javac_text, encoding="utf-8")
        if javac_exit:
            vcs = parse_check(javac_text)
            status, exit_code, proof_text = "COMPILE_FAILED", javac_exit, javac_text
        elif verification_mode == "compile":
            exit_code, proof_text, status, vcs = 0, javac_text, "COMPILED", []
        else:
            exit_code, proof_text = verify(source, mode=verification_mode)
            (attempt_dir / f"{verification_mode}.log").write_text(proof_text, encoding="utf-8")
            classified = classify(exit_code)
            status = ("STATIC_CHECKED" if verification_mode == "check" and exit_code == 0
                      else classified)
            if verification_mode == "esc" and status == "VERIFIED" and has_dropped_vc(proof_text):
                status = "VACUOUS_VERIFIED"
            vcs = ((parse_vcs(proof_text) if verification_mode == "esc" else parse_check(proof_text))
                   if exit_code else [])
        rows = [{"file": vc.file, "line": vc.line, "category": vc.category,
                 "method": vc.method, "detail": vc.detail, "raw": vc.raw} for vc in vcs]
        attempt = {"attempt": number, "status": status, "exit_code": exit_code,
                   "model": used_model, "tokens": usage, "candidate_hash": sha256_text(transformed),
                   "contract_hash": sha256_text("\n".join(_surface(stub)["clauses"])),
                   "vcs": rows, "accepted_passes": accepted_passes or [],
                   "postprocess": pass_report}
        attempts.append(attempt)
        history.append((transformed, vcs, proof_text))
        final_code = transformed
        publish({"type": "implementation_attempt", **attempt})

    final_status = attempts[-1]["status"] if attempts else "NO_ATTEMPT"
    result = {"final_status": final_status, "stop_reason": stop_reason,
              "class_name": cname, "attempts": attempts, "tokens": total,
              "implementation_code": final_code,
              "implementation_path": str(root / f"{cname}.java") if final_code else "",
              "verifier": "openjml", "verification_backend": "jml",
              "claim": ("DEDUCTIVE_PROOF" if final_status == "VERIFIED" and
                        verification_mode == "esc" else
                        "STATIC_CHECK" if final_status in {"STATIC_CHECKED", "COMPILED"} else
                        "NO_PROOF"),
              "trusted_contract_hash": sha256_text("\n".join(_surface(stub)["clauses"])),
              "native_synthesis": True, "external_handoff_used": False,
              "verification_mode": verification_mode}
    if final_code:
        (root / f"{cname}.java").write_text(final_code, encoding="utf-8")
    (root / "verdict.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Native trusted-JML to verified-Java implementation synthesis")
    parser.add_argument("stub", help="JML-annotated Java scaffold")
    parser.add_argument("--provider", default="glm", choices=["glm", "openai", "ollama"])
    parser.add_argument("--model")
    parser.add_argument("--out")
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--resample-budget", type=int, default=1)
    parser.add_argument("--feedback-budget", type=int, default=4)
    parser.add_argument("--accept-pass", action="append", default=[])
    args = parser.parse_args()
    stub = Path(args.stub).read_text(encoding="utf-8")
    result = synthesize_implementation(
        stub, args.provider, args.model, args.out, args.max_attempts,
        args.resample_budget, args.feedback_budget, args.accept_pass)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["final_status"] == "VERIFIED" else 1)


if __name__ == "__main__":
    main()
