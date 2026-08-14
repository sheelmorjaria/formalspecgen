# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Independent C/ACSL drafting and Frama-C WP verification lane."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import difflib
from pathlib import Path

from . import config
from .llm import LLMError, _chat_fn
from .parse_framac import parse_framac_vcs

_C_BLOCK = re.compile(r"```c\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_JSON_BLOCK = re.compile(r"```json\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_PROVED = re.compile(r"Proved goals:\s*(\d+)\s*/\s*(\d+)", re.IGNORECASE)
C_PASS_NAMES = ("inject_overflow_bounds", "inject_null_checks", "inject_valid_pointers",
                "inject_separated", "inject_loop_assigns")

ACSL_SYSTEM = r"""Draft one bounded C11 API and implementation with ACSL contracts for Frama-C WP.
Return exactly one ```c block and one JSON metadata block. Use /*@ requires, assigns, ensures */.
State pointer validity with \valid or \valid_read, integer bounds, and complete assigns clauses.
For loops provide loop invariant, loop assigns, and loop variant. Do not use dynamic allocation,
recursion, function pointers, concurrency, volatile, unions, casts that change pointer type, inline
assembly, compiler extensions, unchecked pointer arithmetic, or unsigned wraparound as policy.
Do not translate JML syntax. Record assumptions and missing information in JSON."""


def apply_c_passes(code: str, selected=None) -> dict:
    """Apply explicitly accepted, conservative ACSL annotation transformations."""
    requested = set(C_PASS_NAMES if selected is None else selected)
    unknown = sorted(requested.difference(C_PASS_NAMES))
    if unknown:
        raise ValueError("unknown C postprocessor passes: " + ", ".join(unknown))
    transforms = {"inject_overflow_bounds": _inject_overflow_bounds,
                  "inject_null_checks": _inject_null_checks,
                  "inject_valid_pointers": _inject_valid_pointers,
                  "inject_separated": _inject_separated,
                  "inject_loop_assigns": _promote_loop_assigns_markers}
    original = current = code; reports = []
    for name in C_PASS_NAMES:
        if name not in requested: continue
        before = current; current = transforms[name](current)
        report = {"name": name, "changed": current != before}
        if current != before:
            report["diff"] = "\n".join(difflib.unified_diff(
                before.splitlines(), current.splitlines(),
                fromfile=f"before/{name}", tofile=f"after/{name}", lineterm=""))
        reports.append(report)
    changed = current != original
    return {"original_code": original, "code": current, "changed": changed,
            "passes": reports, "warnings": lint_acsl(current),
            "proof_relevant_change": changed, "requires_human_acceptance": changed,
            "accepted": False, "claim": "TRANSFORMATION"}


def _inject_null_checks(code: str) -> str:
    """Require validity only for pointer parameters directly dereferenced by a function body."""
    function = re.compile(r"(?m)^(?P<indent>\s*)(?P<ret>[A-Za-z_]\w*(?:\s+\w+)*)\s+"
                          r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{")
    for match in reversed(list(function.finditer(code))):
        body_end = _matching_c_brace(code, match.end() - 1)
        if body_end is None: continue
        body = code[match.end():body_end]; facts = []
        for raw in match["params"].split(","):
            pointer = re.search(
                r"(?P<const>\bconst\b)?[^,;()]*\*\s*(?P<name>[A-Za-z_]\w*)\s*$", raw.strip())
            if not pointer: continue
            name = pointer["name"]
            if not re.search(rf"(?:\*\s*{re.escape(name)}\b|\b{re.escape(name)}\s*\[)", body):
                continue
            facts.append(rf"\{'valid_read' if pointer['const'] else 'valid'}({name})")
        contract = _attached_contract(code, match.start())
        if not facts or not contract: continue
        additions = [fact for fact in facts if fact not in contract["body"]]
        if additions:
            point = contract.start("body")
            insertion = "".join(f" requires {fact};\n" for fact in additions)
            code = code[:point] + insertion + code[point:]
    return code


def _inject_valid_pointers(code: str) -> str:
    """Add base validity plus justified contiguous validity for direct ``ptr[idx]`` access."""
    code = _inject_null_checks(code)
    function = re.compile(r"(?m)^(?P<indent>\s*)(?P<ret>[A-Za-z_]\w*(?:\s+\w+)*)\s+"
                          r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{")
    for match in reversed(list(function.finditer(code))):
        body_end = _matching_c_brace(code, match.end() - 1)
        if body_end is None: continue
        body = code[match.end():body_end]; contract = _attached_contract(code, match.start())
        if not contract: continue
        pointer_names = [pointer["name"] for raw in match["params"].split(",")
                         for pointer in [re.search(r"\*\s*(?P<name>[A-Za-z_]\w*)\s*$", raw.strip())]
                         if pointer]
        additions = []
        for name in pointer_names:
            for index in re.findall(rf"\b{re.escape(name)}\s*\[\s*([A-Za-z_]\w*)\s*\]", body):
                if not re.search(rf"\b{re.escape(index)}\b", match["params"]):
                    continue
                for fact in (rf"{index} >= 0", rf"\valid({name} + (0..{index}))"):
                    if fact not in contract["body"] and fact not in additions:
                        additions.append(fact)
        if additions:
            point = contract.start("body")
            code = code[:point] + "".join(f" requires {fact};\n" for fact in additions) + code[point:]
    return code


def _inject_separated(code: str) -> str:
    """Require separation for directly paired pointer parameters.

    The pass only handles ordinary C function declarations and inserts a fact when two or
    more pointer parameters are present. It never guesses relationships across calls.
    """
    function = re.compile(r"(?m)^(?P<indent>\s*)(?P<ret>[A-Za-z_]\w*(?:\s+\w+)*)\s+"
                          r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{")
    for match in reversed(list(function.finditer(code))):
        pointers = []
        for raw in match["params"].split(","):
            pointer = re.search(r"\*\s*(?P<name>[A-Za-z_]\w*)\s*$", raw.strip())
            if pointer:
                pointers.append(pointer["name"])
        if len(pointers) < 2:
            continue
        contract = _attached_contract(code, match.start())
        if not contract:
            continue
        fact = r"\separated(" + ", ".join(pointers) + ")"
        if fact in contract["body"]:
            continue
        point = contract.start("body")
        code = code[:point] + f" requires {fact};\n" + code[point:]
    return code


def _inject_overflow_bounds(code: str) -> str:
    """Derive exact INT_MIN/INT_MAX obligations for direct int/constant arithmetic."""
    code = re.sub(r"(?m)^(?P<indent>\s*)//\s*acsl-requires:\s*(?P<fact>.+?)\s*$",
                  lambda match: f'{match["indent"]}/*@ requires {match["fact"]}; */', code)
    function = re.compile(r"(?m)^(?P<indent>\s*)int\s+\w+\s*\((?P<params>[^)]*)\)\s*\{")
    changed = False
    for match in reversed(list(function.finditer(code))):
        end = _matching_c_brace(code, match.end() - 1)
        if end is None: continue
        body = code[match.end():end]; facts = []
        for name in re.findall(r"(?:^|,)\s*int\s+([A-Za-z_]\w*)", match["params"]):
            for operator, literal in re.findall(
                    rf"\b{re.escape(name)}\s*([+*\-])\s*(-?\d+)\b", body):
                constant = int(literal)
                if operator == "+":
                    fact = (f"{name} <= INT_MAX - {constant}" if constant >= 0 else
                            f"{name} >= INT_MIN - ({constant})")
                elif operator == "-":
                    fact = (f"{name} >= INT_MIN + {constant}" if constant >= 0 else
                            f"{name} <= INT_MAX + ({constant})")
                elif constant == 0:
                    continue
                elif constant > 0:
                    fact = (f"{name} >= INT_MIN / {constant} && "
                            f"{name} <= INT_MAX / {constant}")
                else:
                    fact = (f"{name} >= INT_MAX / {constant} && "
                            f"{name} <= INT_MIN / {constant}")
                if fact not in facts: facts.append(fact)
        contract = _attached_contract(code, match.start())
        if not contract: continue
        additions = [fact for fact in facts if fact not in contract["body"]]
        if additions:
            point = contract.start("body")
            code = code[:point] + "".join(f" requires {fact};\n" for fact in additions) + code[point:]
            changed = True
    if changed and not re.search(r"(?m)^\s*#\s*include\s*<limits\.h>", code):
        code = "#include <limits.h>\n" + code
    return code


def _promote_loop_assigns_markers(code: str) -> str:
    """Promote reviewed markers; never guess pointer alias or loop frame semantics."""
    return re.sub(r"(?m)^(?P<indent>\s*)//\s*acsl-loop-assigns:\s*(?P<frame>.+?)\s*$",
                  lambda match: f'{match["indent"]}/*@ loop assigns {match["frame"]}; */', code)


def _attached_contract(code: str, function_start: int):
    contracts = list(re.finditer(r"/\*@(?P<body>[\s\S]*?)\*/", code[:function_start]))
    if not contracts: return None
    candidate = contracts[-1]
    return candidate if not code[candidate.end():function_start].strip() else None


def _matching_c_brace(code: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{": depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0: return index
    return None


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
        contract = _attached_contract(code, match.start())
        if not contract or "assigns" not in contract["body"]:
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


def check_c_syntax(code: str, timeout: int | None = None) -> dict:
    """Run the strict C11 compile gate without making an ACSL proof claim."""
    findings = lint_acsl(code)
    if any(item["severity"] == "error" for item in findings):
        return {"status": "ACSL_LINT_FAILED", "exit_code": 2, "claim": "NO_PROOF",
                "warnings": findings}
    compiler = shutil.which(config.CC_BIN)
    if not compiler:
        return {"status": "TOOL_MISSING", "exit_code": 127, "claim": "NO_PROOF",
                "message": f"C compiler not found: {config.CC_BIN}", "warnings": findings}
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "candidate.c"
        source.write_text(code, encoding="utf-8")
        try:
            process = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", str(source)],
                capture_output=True, text=True, timeout=timeout or config.FRAMAC_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124, "claim": "NO_PROOF",
                    "warnings": findings}
        except OSError as exc:
            return {"status": "TOOL_ERROR", "exit_code": 127, "claim": "NO_PROOF",
                    "message": str(exc), "warnings": findings}
    output = ((process.stdout or "") + (process.stderr or "")).strip()
    return {"status": "C_CHECKED" if process.returncode == 0 else "C_COMPILE_FAILED",
            "exit_code": process.returncode, "claim": "STATIC_CHECK" if process.returncode == 0 else "NO_PROOF",
            "output": output[-12000:], "warnings": findings}


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
            "provers": config.FRAMAC_PROVERS.split(","),
            "vcs": [item.__dict__ for item in parse_framac_vcs(output)]}
