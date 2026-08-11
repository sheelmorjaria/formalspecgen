# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Independent C/ACSL drafting and Frama-C WP verification lane."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import config
from .llm import LLMError, _chat_fn

_C_BLOCK = re.compile(r"```c\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_JSON_BLOCK = re.compile(r"```json\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_PROVED = re.compile(r"Proved goals:\s*(\d+)\s*/\s*(\d+)", re.IGNORECASE)

ACSL_SYSTEM = r"""Draft one bounded C11 API and implementation with ACSL contracts for Frama-C WP.
Return exactly one ```c block and one JSON metadata block. Use /*@ requires, assigns, ensures */.
State pointer validity with \valid or \valid_read, integer bounds, and complete assigns clauses.
For loops provide loop invariant, loop assigns, and loop variant. Do not use dynamic allocation,
recursion, function pointers, concurrency, volatile, unions, casts that change pointer type, inline
assembly, compiler extensions, unchecked pointer arithmetic, or unsigned wraparound as policy.
Do not translate JML syntax. Record assumptions and missing information in JSON."""


def lint_acsl(code: str) -> list[dict]:
    rules = [
        (r"\b(?:malloc|calloc|realloc|free)\s*\(", "dynamic-memory", "Dynamic allocation is outside the reviewed ACSL subset."),
        (r"\b(?:pthread_|_Atomic|volatile\b)", "concurrency", "Concurrency and volatile memory require a separate memory model."),
        (r"\b(?:asm|__asm__)\b", "assembly", "Inline assembly is not represented by the WP model."),
        (r"\b(?:strcpy|sprintf|gets)\s*\(", "unsafe-library", "Use a bounded, specified operation."),
    ]
    findings = []
    for pattern, category, message in rules:
        for match in re.finditer(pattern, code):
            findings.append({"code": f"acsl-{category}", "severity": "error",
                             "line": code.count("\n", 0, match.start()) + 1, "message": message})
    for match in re.finditer(r"(?m)^\s*(?:[\w*]+\s+)+\w+\s*\([^;]*\)\s*\{", code):
        context = code[max(0, match.start() - 1000):match.start()]
        contract = re.search(r"/\*@(.+?)\*/\s*$", context, re.DOTALL)
        if not contract or "assigns" not in contract.group(1):
            findings.append({"code": "acsl-missing-assigns", "severity": "error",
                             "line": code.count("\n", 0, match.start()) + 1,
                             "message": "Every defined function needs an explicit ACSL assigns clause."})
    return findings


def draft_acsl(requirement: str, provider: str = "glm") -> dict:
    try:
        raw, model, usage = _chat_fn(provider)(
            [{"role": "system", "content": ACSL_SYSTEM},
             {"role": "user", "content": f"Requirement:\n{requirement}"}], None, 0.1)
    except LLMError as exc:
        return {"status": "API_ERROR", "message": str(exc), "language": "c", "warnings": []}
    match = _C_BLOCK.search(raw)
    if not match:
        return {"status": "PARSE_ERROR", "message": "model did not return one fenced C block",
                "language": "c", "warnings": []}
    metadata = {"assumptions": [], "missing_info_questions": []}
    json_match = _JSON_BLOCK.search(raw)
    if json_match:
        try:
            metadata.update(json.loads(json_match.group(1)))
        except json.JSONDecodeError:
            metadata["missing_info_questions"].append("The model returned malformed metadata JSON.")
    code = match.group(1).strip() + "\n"
    return {"status": "DRAFTED", "code": code, "language": "c", "model": model,
            "usage": usage, "warnings": lint_acsl(code), **metadata}


def verify_framac(code: str, timeout: int | None = None) -> dict:
    findings = lint_acsl(code)
    if any(item["severity"] == "error" for item in findings):
        return {"status": "ACSL_LINT_FAILED", "exit_code": 2, "claim": "NO_PROOF",
                "warnings": findings}
    framac = shutil.which(config.FRAMAC_BIN)
    compiler = shutil.which(config.CC_BIN)
    if not compiler:
        return {"status": "TOOL_MISSING", "exit_code": 127, "claim": "NO_PROOF",
                "message": f"C compiler not found: {config.CC_BIN}"}
    if not framac:
        return {"status": "TOOL_MISSING", "exit_code": 127, "claim": "NO_PROOF",
                "message": f"Frama-C not found: {config.FRAMAC_BIN}"}
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "candidate.c"
        source.write_text(code, encoding="utf-8")
        try:
            compiled = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", str(source)],
                                      capture_output=True, text=True, timeout=timeout or config.FRAMAC_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124, "claim": "NO_PROOF"}
        except OSError as exc:
            return {"status": "TOOL_ERROR", "exit_code": 127, "claim": "NO_PROOF", "message": str(exc)}
        if compiled.returncode:
            output = ((compiled.stdout or "") + (compiled.stderr or "")).strip()
            return {"status": "C_COMPILE_FAILED", "exit_code": compiled.returncode,
                    "claim": "NO_PROOF", "output": output[-12000:]}
        command = [framac, "-wp", "-wp-rte", "-wp-prover", config.FRAMAC_PROVERS, str(source)]
        try:
            process = subprocess.run(command, capture_output=True, text=True,
                                     timeout=timeout or config.FRAMAC_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124, "claim": "NO_PROOF"}
        except OSError as exc:
            return {"status": "TOOL_ERROR", "exit_code": 127, "claim": "NO_PROOF", "message": str(exc)}
    output = ((process.stdout or "") + (process.stderr or "")).strip()
    summaries = _PROVED.findall(output)
    proved, total = (tuple(map(int, summaries[-1])) if summaries else (0, 0))
    rte_caveats = re.findall(r"Skipped RTE guards:\s*([^\n]+)", output)
    verified = process.returncode == 0 and total > 0 and proved == total
    return {"status": "VERIFIED" if verified else "VERIFY_FAILED",
            "exit_code": process.returncode, "claim": "DEDUCTIVE_PROOF" if verified else "NO_PROOF",
            "proved_goals": proved, "total_goals": total, "command": command,
            "output": output[-12000:], "warnings": findings,
            "memory_model": "Frama-C WP default typed C memory model",
            "runtime_errors": "PARTIAL" if rte_caveats else "GENERATED",
            "rte_caveats": rte_caveats,
            "provers": config.FRAMAC_PROVERS.split(",")}
