# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Inductive loop verification: k-induction over ESBMC for C/C++ loops.

The prover never unrolls the loop. Two loop-free harnesses are generated
deterministically — ESTABLISHMENT (the invariant holds for the state at loop
entry) and STEP (assume invariant + loop guard, execute one body copy, assert
the invariant) — and ESBMC checks each with a single unwind. Both passing
means the invariant is inductive over this loop: an unbounded result for the
fragment, honestly scoped to the invariant's inductiveness. Whether the
invariant is STRONG ENOUGH for the property the reviewer cares about is a
human-accepted assumption, recorded as such.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ESBMC_AVAILABLE = shutil.which("esbmc") is not None

_LOOP_HEAD = re.compile(r"while\s*\((?P<cond>[^{}()]+)\)\s*\{")
_NESTED_BLOCK = re.compile(r"\{[^{}]*\}")
_COUNTER_TOKEN = re.compile(r"\b[a-z_]\w*\b")

_INVARIANT_PROMPT = (
    "Propose ONE inductive loop invariant (C++ boolean expression over the "
    "loop's variables, no side effects) for the loop below. It must hold at "
    "loop entry and be preserved by each iteration. Reply with the bare "
    "expression only.")


def _brace_matched(text: str, start: int) -> tuple[str, int]:
    depth, index = 1, start
    while index < len(text) and depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    return text[start:index - 1], index


def extract_loops(code: str) -> list[dict]:
    """Simple ``while (cond) { body }`` loops; nested loops refuse (the
    one-step harness would itself need an unwind over the inner loop)."""
    loops = []
    for match in _LOOP_HEAD.finditer(code):
        condition = match.group("cond").strip()
        body, _ = _brace_matched(code, match.end())
        if "{" in body or "}" in body:        # nested control flow in body
            continue
        if ";" not in body:                   # nothing happens: nothing to prove
            continue
        counter = _counter_of(condition)
        if counter is None:                   # constant guard: no counter to induct over
            continue
        init = _counter_init(code, match.start(), counter)
        loops.append({"condition": condition, "body": body.strip(),
                      "counter": counter, "init": init})
    return loops


def _counter_init(code: str, before: int, counter: str) -> str | None:
    """The literal the counter is set to before the loop (``int i = 0;``)."""
    assignments = re.findall(
        rf"(?:int\s+)?{re.escape(counter)}\s*=\s*(-?\d+)\s*;", code[:before])
    return assignments[-1] if assignments else None


def _declarations(loop: dict, invariant: str) -> list[str]:
    """Nondet declarations for every free identifier but the counter."""
    names = sorted({token for token in _COUNTER_TOKEN.findall(
        f"{invariant} {loop['condition']}")}
        - {loop["counter"], "true", "false", "and", "or", "not", "max", "min"})
    return [f"    int {name} = __VERIFIER_nondet_int();" for name in names]


def _counter_of(condition: str) -> str | None:
    """The first simple identifier in the loop condition is the counter."""
    for token in _COUNTER_TOKEN.findall(condition):
        if token not in {"true", "false", "and", "or", "not"}:
            return token
    return None


def build_induction_harnesses(code: str, loop: dict, invariant: str
                              ) -> tuple[str, str]:
    """(establishment, step) loop-free C++ harnesses for ESBMC.

    Establishment asserts the invariant for the program's OWN entry state
    (the counter's literal initialization when the source provides one);
    step assumes invariant + guard over a nondet state, executes one body
    copy, and asserts preservation.
    """
    counter_decl = (f"    int {loop['counter']} = {loop['init']};"
                    if loop.get("init") is not None else
                    f"    int {loop['counter']} = __VERIFIER_nondet_int();")
    others = "\n".join(_declarations(loop, invariant))
    establishment = f"""#include <cassert>
extern int __VERIFIER_nondet_int();
int main() {{
{counter_decl}
{others}
    // establishment: the invariant holds at loop entry
    assert(({invariant}));
    return 0;
}}
"""
    step = f"""#include <cassert>
extern int __VERIFIER_nondet_int();
int main() {{
    int {loop['counter']} = __VERIFIER_nondet_int();
{others}
    // assume the loop invariant and the loop guard
    if (!({invariant})) return 0;
    if (!({loop['condition']})) return 0;
    // one copy of the loop body
    {loop['body']}
    // preservation: the invariant survives the iteration
    assert(({invariant}));
    return 0;
}}
"""
    return establishment, step


def run_esbmc(code: str, unwind: int = 1) -> dict:
    """One bounded ESBMC run over a loop-free harness (unwind 1 suffices)."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory(prefix="formalspecgen-unbounded-") as d:
        path = Path(d) / "harness.cpp"
        path.write_text(code, encoding="utf-8")
        result = subprocess.run(["esbmc", str(path), "--unwind", str(unwind),
                                 "--z3"], capture_output=True, text=True,
                                timeout=180)
    output = (result.stdout or "") + (result.stderr or "")
    verified = result.returncode == 0 and "VERIFICATION SUCCESSFUL" in output
    return {"status": "VERIFIED" if verified else "FAILED",
            "exit_code": result.returncode, "output": output[-4000:]}


def _propose_invariant(code: str, loop: dict, provider: str) -> str:
    from .llm import _chat_fn, strip_fence
    raw, _, _ = _chat_fn(provider)([
        {"role": "system", "content": _INVARIANT_PROMPT},
        {"role": "user", "content": f"while ({loop['condition']}) "
                                    f"{{ {loop['body']} }}"}], None, 0.1)
    return strip_fence(raw).strip()


def verify_unbounded(source: str | Path, invariant: str | None = None, *,
                     provider: str = "ollama") -> dict:
    """Prove an invariant inductive over each simple loop in the source."""
    path = Path(source)
    if not path.is_file():
        return {"status": "UNBOUNDED_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(path)}
    if not ESBMC_AVAILABLE:
        return {"status": "UNBOUNDED_FAILED", "claim": "NO_PROOF",
                "code": "esbmc_unavailable",
                "message": "install ESBMC to run induction harnesses"}
    code = path.read_text(encoding="utf-8")
    loops = extract_loops(code)
    if not loops:
        return {"status": "UNBOUNDED_FAILED", "claim": "NO_PROOF",
                "code": "no_verifiable_loop",
                "message": "no simple while-loop found (nested or empty "
                           "bodies are outside the induction shape)"}

    invariant_source = "human_supplied" if invariant is not None else None
    if invariant is None:
        try:
            invariant = _propose_invariant(code, loops[0], provider)
            invariant_source = "llm_proposed"
        except Exception as exc:
            return {"status": "UNBOUNDED_FAILED", "claim": "NO_PROOF",
                    "code": "invariant_generation_failed", "message": str(exc)}
    invariant = invariant.strip().rstrip(";")

    # necessary residual: the invariant must govern the loop's own counter
    for loop in loops:
        if loop["counter"] not in invariant:
            return {"status": "UNBOUNDED_FAILED", "claim": "NO_PROOF",
                    "code": "invariant_rejected",
                    "message": f"invariant must mention the loop counter "
                               f"{loop['counter']!r} to be inductive"}

    proven = []
    for loop in loops:
        establishment, step = build_induction_harnesses(code, loop, invariant)
        if run_esbmc(establishment)["status"] != "VERIFIED":
            return {"status": "UNBOUNDED_FAILED", "claim": "NO_PROOF",
                    "failed_harness": "establishment",
                    "invariant": invariant, "loop": loop["condition"],
                    "message": "the invariant does not hold at loop entry"}
        step_result = run_esbmc(step)
        if step_result["status"] != "VERIFIED":
            return {"status": "UNBOUNDED_FAILED", "claim": "NO_PROOF",
                    "failed_harness": "step",
                    "invariant": invariant, "loop": loop["condition"],
                    "message": "the invariant is not preserved by one "
                               "iteration (not inductive)",
                    "evidence": str(step_result.get("output", ""))[-2000:]}
        proven.append(loop["condition"])

    return {"status": "UNBOUNDED_VERIFIED", "claim": "DEDUCTIVE_PROOF",
            "scope": "unbounded_loop_induction",
            "invariant": invariant, "invariant_source": invariant_source,
            "loops_proved": proven,
            "inductiveness_machine_proved": True,
            "sufficiency_for_property": "human_accepted_assumption",
            "note": "establishment + one-step preservation proved per loop; "
                    "the invariant's adequacy for any external property is "
                    "the reviewer's accepted assumption"}
