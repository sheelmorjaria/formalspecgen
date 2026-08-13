# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Experimental Rust/Prusti drafting with compilation kept distinct from proof."""
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
from .parse_prusti import parse_prusti_vcs

RUST_PASS_NAMES = ("inject_overflow_bounds", "inject_sum_helper", "guard_array_access",
                   "inject_pure", "inject_slice_bounds")

RUST_SYSTEM = r"""Draft a Rust contract scaffold for later Prusti verification.
Return exactly one ```rust block and one ```json block containing assumptions and
missing_info_questions. Use stable, idiomatic Rust traits. Import prusti_contracts::* and use
#[requires(...)] and #[ensures(...)]; use old(...) only in postconditions and body_invariant! for
loops. Prefer &[T] for readers and &mut [T] for exclusive mutation. Never emit raw pointers,
unsafe, unwrap, expect, panic, todo, unimplemented, unchecked indexing, or wildcard matches over
declared enums. Use Option instead of null and Result for fallible operations. Keep overflow checks
enabled and state numeric bounds. Do not implement business logic: prefer trait signatures.
Ownership establishes aliasing constraints, but does not itself prove functional postconditions or
remove the need for pre-state values. Record every interpretation and ambiguity."""

_RUST_BLOCK = re.compile(r"```rust\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_JSON_BLOCK = re.compile(r"```json\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_PRUSTI_ATTRIBUTE = re.compile(
    r"(?m)^[ \t]*#\[(?:requires|ensures|after_expiry|assert_on_expiry|pure|trusted|predicate|invariant)"
    r"(?:\([^\n]*\))?\][ \t]*(?:\r?\n)?"
)
# A source must declare at least one proof obligation before a Prusti exit 0 can
# be reported as verification; #[pure] alone creates no obligation.
_PRUSTI_OBLIGATION = re.compile(
    r"#\[\s*(?:requires|ensures|after_expiry|assert_on_expiry)|body_invariant!|prusti_assert!")


def draft_rust(requirement: str, provider: str = "glm") -> dict:
    """Draft a reviewable contract, then lint and type-check its Rust shape."""
    try:
        raw, model, _usage = _chat_fn(provider)(
            [{"role": "system", "content": RUST_SYSTEM},
             {"role": "user", "content": f"Requirement:\n{requirement}"}], None, 0.1)
    except LLMError as exc:
        return {"status": "API_ERROR", "message": str(exc), "language": "rust",
                "verification_status": "NOT_RUN", "verifier": "prusti", "warnings": []}
    code_match = _RUST_BLOCK.search(raw)
    if not code_match:
        return {"status": "PARSE_ERROR", "message": "model did not return a fenced Rust block",
                "language": "rust", "verification_status": "NOT_RUN",
                "verifier": "prusti", "warnings": []}
    code = code_match.group(1).strip() + "\n"
    metadata = {"assumptions": [], "missing_info_questions": []}
    json_match = _JSON_BLOCK.search(raw)
    if json_match:
        try:
            metadata.update(json.loads(json_match.group(1)))
        except json.JSONDecodeError:
            metadata["missing_info_questions"].append("The model returned malformed metadata JSON.")
    check = check_rust_syntax(code)
    proof = verify_prusti(code) if _prusti_binary() else {
        "status": "NOT_RUN", "exit_code": 127,
        "message": f"Prusti is not installed at {config.PRUSTI_BIN}"}
    status = proof["status"] if proof["status"] != "NOT_RUN" else check["status"]
    return {"status": status, "code": code, "language": "rust",
            "verification_status": proof["status"], "verifier": "prusti",
            "proof": proof, "check": check, "warnings": lint_rust(code), "model": model, **metadata}


def lint_rust(code: str) -> list[dict]:
    """Return conservative, line-addressed Rust contract and idiom warnings."""
    rules = [
        (r"\bunsafe\b|\*const\s|\*mut\s", "rust-unsafe", "error",
         "Unsafe or raw-pointer code requires explicit human review and a dedicated verifier."),
        (r"\.(?:unwrap|expect)\s*\(", "rust-panic-path", "error",
         "Replace unwrap/expect with explicit Result or Option propagation."),
        (r"\b(?:panic|todo|unimplemented)!\s*\(", "rust-panic-path", "error",
         "Generated production scaffolds must not contain deliberate panic paths."),
        (r"\bnull\b|nullptr", "rust-null", "warning", "Represent absence with Option<T>."),
        (r"\.clone\s*\(\)", "rust-clone", "information",
         "Confirm that this clone expresses ownership intent rather than hiding a design issue."),
        (r"\b\w+\[[^\]\n]+\]", "rust-indexing", "warning",
         "Direct indexing may panic; prove the bound or use get/get_mut with explicit handling."),
    ]
    warnings = []
    for pattern, code_name, severity, message in rules:
        for match in re.finditer(pattern, code):
            warnings.append({"code": code_name, "severity": severity,
                             "line": code.count("\n", 0, match.start()) + 1, "message": message})
    lines = code.splitlines()
    for index, line in enumerate(lines):
        if re.search(r"\bpub\s+(?:async\s+)?fn\s+", line):
            context = "\n".join(lines[max(0, index - 4):index])
            if "#[ensures" not in context:
                warnings.append({"code": "rust-missing-postcondition", "severity": "warning",
                                 "line": index + 1,
                                 "message": "Public function has no nearby Prusti postcondition."})
        if re.search(r"\b(?:pub\s+)?fn\s+\w+\s*\([^)]*Vec\s*<", line):
            warnings.append({"code": "rust-contract-vec", "severity": "warning", "line": index + 1,
                             "message": "Prefer &[T] or &mut [T] at contract boundaries unless ownership transfer is required."})
        if re.search(r"\b(?:for|while)\b", line):
            context = "\n".join(lines[max(0, index - 3):index + 1])
            if "body_invariant!" not in context:
                warnings.append({"code": "rust-missing-loop-invariant", "severity": "warning",
                                 "line": index + 1, "message": "Loop has no nearby Prusti body_invariant! fact."})
    pure_functions = set(re.findall(r"#\[pure\][ \t\r\n]*(?:pub\s+)?fn\s+(\w+)", code))
    defined_functions = set(re.findall(r"(?:^|\n)\s*(?:pub\s+)?fn\s+(\w+)\s*\(", code))
    contract_text = "\n".join(re.findall(r"#\[(?:requires|ensures)\(([^\n]*)\)\]", code))
    calls = set(re.findall(r"(?<!\.)\b([a-zA-Z_]\w*)\s*\(", contract_text))
    for helper in sorted((calls & defined_functions) - pure_functions):
        match = re.search(rf"(?:^|\n)\s*(?:pub\s+)?fn\s+{re.escape(helper)}\s*\(", code)
        warnings.append({"code": "rust-missing-pure", "severity": "error",
                         "line": code.count("\n", 0, match.start()) + 1 if match else 1,
                         "message": f"Helper {helper} is used in a contract but is not annotated #[pure]."})
    return warnings


def apply_rust_passes(code: str, selected=None) -> dict:
    """Apply conservative Prusti rewrites and return transparent per-pass diffs."""
    requested = set(RUST_PASS_NAMES if selected is None else selected)
    unknown = sorted(requested.difference(RUST_PASS_NAMES))
    if unknown:
        raise ValueError("unknown Rust postprocessor passes: " + ", ".join(unknown))
    functions = {
        "inject_overflow_bounds": _promote_explicit_bounds,
        "inject_sum_helper": _mark_contract_helpers_pure,
        "guard_array_access": _guard_simple_indexing,
        "inject_pure": _mark_contract_helpers_pure,
        "inject_slice_bounds": _guard_simple_indexing,
    }
    original = current = code
    reports = []
    for name in RUST_PASS_NAMES:
        if name not in requested:
            continue
        before = current
        current = functions[name](current)
        report = {"name": name, "changed": current != before}
        if current != before:
            report["diff"] = "\n".join(difflib.unified_diff(
                before.splitlines(), current.splitlines(),
                fromfile=f"before/{name}", tofile=f"after/{name}", lineterm=""))
        reports.append(report)
    changed = current != original
    return {"original_code": original, "code": current, "changed": changed,
            "passes": reports, "warnings": lint_rust(current),
            "proof_relevant_change": changed, "requires_human_acceptance": changed,
            "accepted": False, "claim": "TRANSFORMATION"}


def _promote_explicit_bounds(code: str) -> str:
    """Promote reviewed facts and derive exact bounds for scalar integer/constant arithmetic."""
    code = re.sub(r"(?m)^(?P<indent>\s*)//\s*prusti-requires:\s*(?P<fact>.+?)\s*$",
                  lambda match: f'{match["indent"]}#[requires({match["fact"]})]', code)
    limits = {"i8": (-128, 127), "i16": (-32768, 32767),
              "i32": (-2147483648, 2147483647),
              "i64": (-9223372036854775808, 9223372036854775807)}
    function = re.compile(r"(?m)^(?P<indent>\s*)(?P<vis>pub\s+)?fn\s+\w+\s*\("
                          r"(?P<params>[^)]*)\)[^\n{;]*\{")
    for match in reversed(list(function.finditer(code))):
        end = _matching_brace(code, match.end() - 1)
        if end is None: continue
        body = code[match.end():end]; facts = []
        for name, kind in re.findall(r"\b([A-Za-z_]\w*)\s*:\s*(i8|i16|i32|i64)\b",
                                     match["params"]):
            lower, upper = limits[kind]
            for operator, literal in re.findall(
                    rf"\b{re.escape(name)}\s*([+*\-])\s*(-?\d+)\b", body):
                fact = _constant_arithmetic_bound(name, operator, int(literal), lower, upper)
                if fact and fact not in facts: facts.append(fact)
        nearby = code[max(0, match.start() - 800):match.start()]
        additions = [fact for fact in facts if f"#[requires({fact})]" not in nearby]
        if additions:
            insertion = "".join(f'{match["indent"]}#[requires({fact})]\n' for fact in additions)
            code = code[:match.start()] + insertion + code[match.start():]
    return code


def _constant_arithmetic_bound(name: str, operator: str, constant: int,
                               minimum: int, maximum: int) -> str | None:
    if operator == "+":
        return (f"{name} <= {maximum - constant}" if constant >= 0 else
                f"{name} >= {minimum - constant}")
    if operator == "-":
        return (f"{name} >= {minimum + constant}" if constant >= 0 else
                f"{name} <= {maximum + constant}")
    if constant == 0: return None
    ceil_div = lambda left, right: -((-left) // right)
    if constant > 0:
        lower, upper = ceil_div(minimum, constant), maximum // constant
    else:
        lower, upper = ceil_div(maximum, constant), minimum // constant
    return f"{name} >= {lower} && {name} <= {upper}"


def _mark_contract_helpers_pure(code: str) -> str:
    contracts = "\n".join(re.findall(r"#\[(?:requires|ensures)\(([^\n]*)\)\]", code))
    calls = set(re.findall(r"(?<!\.)\b([a-zA-Z_]\w*)\s*\(", contracts))
    for name in sorted(calls):
        pattern = re.compile(rf"(?m)^(?P<indent>\s*)(?P<prefix>pub\s+)?fn\s+{re.escape(name)}\s*\(")
        match = pattern.search(code)
        if match and "#[pure]" not in code[max(0, match.start() - 30):match.start()]:
            code = code[:match.start()] + f'{match["indent"]}#[pure]\n' + code[match.start():]
    return code


def _guard_simple_indexing(code: str) -> str:
    """Add only signature-derived usize/slice bounds for direct `slice[index]` accesses."""
    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<vis>pub\s+)?fn\s+(?P<name>\w+)\s*\("
        r"(?P<params>[^)]*)\)(?P<tail>[^\n{;]*)\{"
    )
    for match in reversed(list(pattern.finditer(code))):
        params = match["params"]
        indices = re.findall(r"\b(\w+)\s*:\s*usize\b", params)
        slices = re.findall(r"\b(\w+)\s*:\s*&(?:mut\s+)?\[[^]]+\]", params)
        body_end = _matching_brace(code, match.end() - 1)
        body = code[match.end():body_end if body_end is not None else len(code)]
        facts = [f"{index} < {array}.len()" for array in slices for index in indices
                 if re.search(rf"\b{re.escape(array)}\s*\[\s*{re.escape(index)}\s*\]", body)]
        existing = code[max(0, match.start() - 300):match.start()]
        additions = [fact for fact in facts if f"#[requires({fact})]" not in existing]
        if additions:
            insertion = "".join(f'{match["indent"]}#[requires({fact})]\n' for fact in additions)
            point = match.start()
            code = code[:point] + insertion + code[point:]
    return code


def _matching_brace(code: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def check_rust_syntax(code: str, timeout: int = 60) -> dict:
    """Type-check after erasing known contracts; this deliberately does not claim proof."""
    erased = re.sub(r"(?m)^\s*use\s+prusti_contracts::\*;\s*$", "", code)
    erased = _PRUSTI_ATTRIBUTE.sub("", erased)
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "lib.rs"
        output = Path(directory) / "lib.rmeta"
        source.write_text(erased, encoding="utf-8")
        try:
            process = subprocess.run(
                ["rustc", "--crate-type", "lib", "--edition", "2021", "--emit", "metadata",
                 "-D", "warnings", "-o", str(output), str(source)],
                capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return {"status": "TOOL_MISSING", "exit_code": 127,
                    "message": "rustc is not installed; Prusti verification was not attempted"}
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124, "message": "rustc check timed out"}
    text = ((process.stdout or "") + (process.stderr or "")).strip()
    return {"status": "RUST_CHECKED" if process.returncode == 0 else "RUST_CHECK_FAILED",
            "exit_code": process.returncode, "output": text[-8000:],
            "disclaimer": "Prusti annotations were erased for this Rust compiler check; no contract was proved."}


def verify_prusti(code: str, timeout: int | None = None) -> dict:
    """Run the real Prusti verifier and preserve its diagnostics as authoritative evidence."""
    binary = _prusti_binary()
    if binary is None:
        return {"status": "TOOL_MISSING", "exit_code": 127,
                "message": f"Prusti executable not found at {config.PRUSTI_BIN}"}
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "contract.rs"
        source.write_text(code, encoding="utf-8")
        try:
            process = subprocess.run(
                [str(binary), "--edition=2021", str(source)], cwd=binary.parent,
                capture_output=True, text=True, timeout=timeout or config.PRUSTI_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124,
                    "message": f"Prusti verification timed out after {timeout or config.PRUSTI_TIMEOUT}s"}
        except OSError as exc:
            return {"status": "TOOL_ERROR", "exit_code": 127, "message": str(exc)}
    output = ((process.stdout or "") + (process.stderr or "")).strip()
    vcs = parse_prusti_vcs(output)
    result = {"status": "VERIFIED" if process.returncode == 0 else "VERIFY_FAILED",
              "exit_code": process.returncode, "output": output[-12000:],
              "vcs": [item.__dict__ for item in vcs]}
    if result["status"] == "VERIFIED" and not _PRUSTI_OBLIGATION.search(code):
        # Mirror the OpenJML vacuity guard: exit 0 over a source with no contract
        # discharges no proof obligation and must not be claimed as proof.
        result["status"] = "VACUOUS_VERIFIED"
        result["vacuity_note"] = (
            "Prusti exited 0 but the source declares no #[requires]/#[ensures]/expiry "
            "contract and no body_invariant!/prusti_assert!; no obligation was discharged")
    return result


def _prusti_binary() -> Path | None:
    configured = Path(config.PRUSTI_BIN)
    if configured.exists():
        return configured.resolve()
    discovered = shutil.which(config.PRUSTI_BIN)
    return Path(discovered).resolve() if discovered else None
