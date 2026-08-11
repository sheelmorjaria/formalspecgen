# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""LLM provider abstraction.

Transport (_glm_chat, LLMError, strip_fence) is ported from formalspecDD unchanged; the
generation/repair functions and prompts are rewritten for the NL->JML direction (DD's
were "fill Java bodies"; ours is "draft JML specs from natural language").

Output contract: the model emits TWO fenced blocks — a ```java block (the JML-annotated
skeleton stub, which is what we validate and what formalspecDD consumes) and a ```json
block ({assumptions, missing_info_questions}). Keeping code OUT of JSON string fields
avoids the fragile-escaping failure mode called out in the design critique.
"""
import json
import re
import urllib.error
import urllib.request

from . import config
from .schemas import SpecDraft
from .limitations import prompt_guardrails

# --- NL -> JML system prompt -----------------------------------------------
SYSTEM = """You are a formal-specification engineer. Given a natural-language requirement, \
draft a JML (Java Modeling Language) specification for OpenJML 21 that a human will review \
and refine. Do NOT implement method logic — only the contract matters.

Emit exactly TWO fenced blocks and nothing else:

1. A ```java block: a COMPLETE, COMPILABLE Java file containing the spec:
   - Exactly one public class (name it from the NL).
   - Private fields, each annotated /*@ spec_public @*/ so JML clauses may reference them.
   - Method SIGNATURES ONLY with trivial bodies: void methods have an empty body {}; value-
     returning methods return a type-correct default (return 0; / return false; / return null;).
   - JML annotations ABOVE each constructor/method: //@ requires, //@ ensures, //@ assignable,
     //@ signals; and a class-level //@ public invariant where the NL states an invariant.
   - For any loop body, add //@ loop_invariant and //@ decreases.
     NOTE (OpenJML 21): `assignable` is a METHOD-contract keyword, NOT a loop keyword.

2. A ```json block: {"assumptions": [...], "missing_info_questions": [...]}
   - assumptions: every interpretation you had to choose (e.g. "balance is non-negative").
   - missing_info_questions: ambiguities that affect correctness (e.g. "can the amount be
     negative?"). ASK rather than guess.

Hard rules:
- Every name used in a JML clause MUST be a declared field or parameter — no invented symbols.
- Do NOT invent fields, bounds, or behaviors the NL does not imply. If a boundary is
  unspecified, put it in missing_info_questions and the interpretation in assumptions; do NOT
  silently add a requires/ensures for it.
- Keep arithmetic within int range.
- Use only JML valid under OpenJML 21.
- Keep every `//@ requires`, `//@ ensures`, `//@ assignable`, and `//@ signals` clause on
  ONE complete line ending in `;`. Never continue a JML clause with an ordinary `//` comment.
- Every value-returning method must have a postcondition that explicitly constrains `\\result`.
  For a Boolean success/failure API, relate `\\result` to the pre-state feasibility condition,
  then guard successful and failed state transitions with `\\result` and `!\\result`.
- If the requirement defines an input as a normal failure that returns false, DO NOT exclude
  that input with `requires`; it must remain in the method domain so the false behavior applies.
  Reserve `requires` for caller obligations and exceptional-behavior case partitions.
- Never use `\\old(...)` in `requires`; preconditions already refer to the method pre-state.

QUANTIFIERS — when the NL describes an aggregate or a universal/existential property over a
collection, express it DIRECTLY as a JML quantifier in the clause. Do NOT paraphrase it as a
loop, recursion, or prose; the contract itself must be the quantified expression.
Quantifiers: \\forall, \\exists, \\sum, \\product, \\min, \\max. General forms (adapt the
bound variable, range, and body to the requirement):
  (\\sum int j; 0 <= j && j < n; xs[j])                         // sum of the elements
  (\\product int j; 0 <= j && j < n; xs[j])                     // product of the elements
  (\\forall int j; 0 <= j && j < n - 1; xs[j] <= xs[j + 1])     // every adjacent pair ordered
  (\\exists int j; 0 <= j && j < n; xs[j] == t)                 // the collection contains t
  (\\forall int d; d > 0 && n % d == 0; d <= r)                 // r is the greatest such divisor
All three parts — bound variable + range predicate + body — go INSIDE the parentheses.

Example —

Requirement: "A counter starts at 0, can be incremented by a non-negative amount, never
exceeds 1000, and reports its current value."
```java
public class Counter {
    private /*@ spec_public @*/ int count;

    //@ public invariant 0 <= count && count <= 1000;

    //@ ensures count == 0;
    public Counter() {}

    //@ requires n >= 0;
    //@ requires count + n <= 1000;
    //@ assignable count;
    //@ ensures count == \\old(count) + n;
    public void add(int n) {}

    //@ ensures \\result == count;
    public /*@ pure */ int get() { return 0; }
}
```
```json
{ "assumptions": ["n is a non-negative integer"], "missing_info_questions": ["what should add do when count + n would exceed 1000?"] }
```

Boolean state-transition example — when overflow is a defined `false` result, it MUST remain
inside the method domain. Do not turn the feasibility condition into a `requires` clause:
```java
public class BoundedBalance {
    private /*@ spec_public @*/ long balance;
    //@ public invariant 0 <= balance && balance <= 9000L;

    //@ requires amount > 0;
    //@ assignable balance;
    //@ ensures \\result <==> amount <= 9000L - \\old(balance);
    //@ ensures \\result ==> balance == \\old(balance) + amount;
    //@ ensures !\\result ==> balance == \\old(balance);
    public boolean deposit(long amount) { return false; }
}
```
Notice that every Boolean outcome is connected to both feasibility and its frame-preserving
state transition. A clean syntax check without these `\\result` clauses is incomplete.

Think step by step about entities, state, and each method's contract, then emit the two blocks."""

REPAIR_SYSTEM = SYSTEM + """

REPAIR MODE: you are given a previous JML stub that FAILED `openjml -check`, the raw
diagnostics, and the original requirement. Diagnostics may also contain deterministic
`specification lint` findings for incomplete or vacuous contracts even when syntax passed.
Diagnose the root cause (undeclared name, bad
JML syntax, type mismatch, malformed annotation), then emit the corrected ```java and
```json blocks.
- Fix syntax/type/scope errors. Do NOT weaken or change the spec's intent; if an error shows
  the spec itself is wrong, correct it minimally and record the change in assumptions.
- A very common failure is referencing a field/parameter name that is misspelled or not declared.
"""


class LLMError(Exception):
    """Raised on a provider API error (auth, billing, rate-limit, network/timeout)."""
    def __init__(self, code, message, http_status=None):
        self.code = code
        self.message = message
        self.http_status = http_status
        super().__init__(f"[{code}] {message}")


_FENCE = re.compile(r"```(?:java|Java)?\s*\n(.*?)```", re.DOTALL)
_JAVA_FENCE = re.compile(r"```(?:java|Java)\s*\n(.*?)```", re.DOTALL)
_JSON_FENCE = re.compile(r"```(?:json|JSON)\s*\n(.*?)```", re.DOTALL)


def strip_fence(text: str) -> str:
    m = _FENCE.search(text)
    return m.group(1) if m else text


def _first_json_object(s: str):
    """Best-effort: pull the first balanced {...} substring out of s and parse it."""
    start = s.find("{")
    if start < 0:
        return {}
    depth, in_str, esc = 0, False, False
    for i in range(start, len(s)):
        c = s[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(s[start:i + 1])
                    except Exception:
                        return {}
    return {}


def _parse_draft(content: str) -> SpecDraft:
    """Extract the ```java stub and ```json metadata from an LLM response."""
    jm = _JAVA_FENCE.search(content)
    stub = jm.group(1).strip() if jm else strip_fence(content).strip()

    meta = {}
    jsm = _JSON_FENCE.search(content)
    if jsm:
        meta = _first_json_object(jsm.group(1))
    else:
        # A Java class body contains braces before trailing unfenced JSON. Locate a
        # metadata-shaped object rather than incorrectly accepting the first `{}`.
        metadata_start = re.search(
            r'\{\s*"(?:assumptions|missing_info_questions)"\s*:', content)
        meta = _first_json_object(content[metadata_start.start():] if metadata_start else content)
    return SpecDraft(
        stub=stub,
        assumptions=list(meta.get("assumptions") or []),
        missing_info=list(meta.get("missing_info_questions") or []),
    )


def _post_chat(base_url, api_key, messages, model, temperature, timeout, extra_body=None):
    """POST {base_url}/chat/completions — shared across providers (all OpenAI-compatible).

    Retries on transient empty content (common with reasoning models); raises
    LLMError(EMPTY_CONTENT) if still empty after retries, so an empty/truncated answer can
    never become a fake VERIFIED. Structure ported from formalspecDD's _post_chat; Gen keeps
    its thinking-disabled (GLM) + EMPTY_CONTENT guard.
    """
    body = {"model": model, "temperature": temperature, "max_tokens": 8192, "messages": messages}
    if extra_body:
        body.update(extra_body)
    req = urllib.request.Request(
        base_url + "/chat/completions", data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    finish = None
    try:
        content, used, usage = "", model, {}
        for _ in range(4):  # retry up to 3× on empty content
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = json.loads(r.read().decode())
            choice = j["choices"][0]
            content = (choice.get("message", {}) or {}).get("content") or ""
            finish = choice.get("finish_reason")
            used, usage = j.get("model", model), j.get("usage", {})
            if content.strip():
                break
        if not content.strip():
            raise LLMError("EMPTY_CONTENT",
                           f"model returned empty content (finish_reason={finish!r}) after "
                           f"retries; likely max_tokens exhausted by reasoning", None)
        return content, used, usage
    except urllib.error.HTTPError as e:
        msg = e.reason
        try:
            ej = json.loads(e.read().decode())
            err = ej.get("error", {})
            msg = err.get("message", e.reason)
            code = err.get("code", str(e.code))
        except Exception:
            code = str(e.code)
        raise LLMError(code, msg, e.code)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise LLMError("NETWORK", f"request failed/timed out after {timeout}s: {e}")


def _glm_chat(messages, model, temperature):
    # z.ai reasoning models: disable deep thinking (burns tokens / 524s the gateway).
    extra = {"thinking": {"type": "disabled"}} if config.GLM_THINKING == "disabled" else None
    return _post_chat(config.GLM_BASE_URL, config.GLM_API_KEY, messages,
                      model or config.GLM_MODEL, temperature, config.LLM_TIMEOUT, extra)


def _openai_chat(messages, model, temperature):
    return _post_chat(config.OPENAI_BASE_URL, config.OPENAI_API_KEY, messages,
                      model or config.OPENAI_MODEL, temperature, config.LLM_TIMEOUT)


def _ollama_chat(messages, model, temperature):
    return _post_chat(config.OLLAMA_BASE_URL, config.OLLAMA_API_KEY, messages,
                      model or config.OLLAMA_MODEL, temperature, config.LLM_TIMEOUT)


def _chat_fn(provider):
    """Return the chat function for a provider (glm | openai | ollama). Default glm."""
    if provider == "openai":
        return _openai_chat
    if provider == "ollama":
        return _ollama_chat
    return _glm_chat


def glm_generate_spec(nl, model=None, temperature=0.2, chat_fn=None):
    """Fresh NL -> SpecDraft. Returns (draft, model_used, usage).

    chat_fn routes to a provider (default GLM); the orchestrator passes _chat_fn(provider)
    and retries with a fallback provider on LLMError.
    """
    marker = "\nClarifications (human-provided and authoritative):\n"
    if marker in nl:
        original, clarifications = nl.split(marker, 1)
        requirement = ("Original requirement:\n" + original.strip() +
                       "\n\nHuman clarifications (authoritative; resolve conflicts in their favor):\n" +
                       clarifications.strip())
    else:
        requirement = "Original requirement:\n" + nl
    messages = [
        {"role": "system", "content": SYSTEM + prompt_guardrails(nl)},
        {"role": "user", "content":
         "Draft a JML specification from the requirement and any explicit clarifications below.\n\n" +
         requirement},
    ]
    content, used, usage = (chat_fn or _glm_chat)(messages, model, temperature)
    return _parse_draft(content), used, usage


def glm_repair_spec(prev_stub, errors, nl, model=None, temperature=0.2, chat_fn=None):
    """Feedback repair: previous stub + raw -check diagnostics + NL -> corrected SpecDraft.
    Returns (draft, model_used, usage). chat_fn selects the provider (default GLM)."""
    targeted = ""
    if ("unconstrained-boolean-result" in errors or
            "boolean-failure-excluded-by-precondition" in errors or
            "unreachable-exceptional-behavior" in errors):
        targeted = r"""

MANDATORY BOOLEAN-RESULT REPAIR:
- Every Boolean method named by the lint diagnostics MUST contain `\result` in its ensures clauses.
- Use this logical shape, replacing FEASIBLE, SUCCESS_STATE, and UNCHANGED with declared expressions:
  //@ ensures \result <==> FEASIBLE_IN_THE_PRE_STATE;
  //@ ensures \result ==> SUCCESS_STATE;
  //@ ensures !\result ==> UNCHANGED_STATE;
- A case specified to return false (insufficient funds, overflow, or capacity failure) is NOT a
  precondition violation. Remove any `requires` clause that excludes that case.
- Avoid overflow while stating feasibility: prefer `amount <= MAX - \old(balance)` over
  `\old(balance) + amount <= MAX`.
Do not finish until each diagnosed Boolean method follows this rule.
"""
    messages = [
        {"role": "system", "content": REPAIR_SYSTEM + prompt_guardrails(nl + "\n" + prev_stub)},
        {"role": "user", "content":
         "Original natural-language requirement:\n" + nl + "\n\n"
         "Your previous JML stub FAILED `openjml -check` with these diagnostics:\n```\n"
         + errors + "\n```\n" + targeted + "\n"
         "Your previous stub:\n```java\n" + prev_stub + "\n```\n\n"
         "Fix the stub so `openjml -check` is clean. Emit the corrected ```java and ```json blocks."},
    ]
    content, used, usage = (chat_fn or _glm_chat)(messages, model, temperature)
    return _parse_draft(content), used, usage


INVARIANT_SYSTEM = """You propose JML loop specifications for OpenJML 21.
Given Java/JML source and one while-loop line, return only one or more `//@ loop_invariant ...;`
lines followed by exactly one `//@ decreases ...;` line. Use only variables visible in the
source. Every invariant must hold before the first iteration and be preserved by one iteration.
Do not use \\result, do not repeat the negated loop guard, and do not include markdown fences."""


def suggest_loop_invariant(code, loop_line, model=None, temperature=0.0, chat_fn=None):
    guardrails = prompt_guardrails(code + "\n" + loop_line)
    messages = [
        {"role": "system", "content": INVARIANT_SYSTEM + guardrails},
        {"role": "user", "content": f"Source:\n```java\n{code}\n```\n\nLoop line:\n{loop_line}"},
    ]
    content, used, usage = (chat_fn or _glm_chat)(messages, model, temperature)
    lines = [line.strip() for line in strip_fence(content).splitlines()
             if line.strip().startswith("//@")]
    if not lines or not any("loop_invariant" in line for line in lines):
        raise LLMError("INVALID_INVARIANT", "model did not return a JML loop invariant")
    return "\n".join(lines), used, usage


RAC_TEST_SYSTEM = """Write a small JUnit 5 test class for the supplied JML-annotated Java class.
Exercise valid boundary inputs and likely failing cases related to the supplied ESC diagnostics.
When testing an orchestrator, create deterministic in-memory fake implementations of its interfaces;
include timeout/failure fakes when the contracts permit those environmental outcomes.
Before every invocation print one single line `FORMALSPEC_INPUT: <method>(<literal inputs>)` so
runtime evidence can be shown in the IDE. Use only public APIs. Return only a complete Java file
in a java fence. OpenJML RAC reports violations to output and may not throw AssertionError, so use
ordinary assertions for expected valid behavior rather than assertThrows for JML violations."""


def generate_rac_tests(code, class_name, diagnostics, model=None, temperature=0.1, chat_fn=None):
    messages = [
        {"role": "system", "content": RAC_TEST_SYSTEM + prompt_guardrails(code)},
        {"role": "user", "content":
         f"Class under test: {class_name}\nESC diagnostics:\n{diagnostics}\n\n```java\n{code}\n```"},
    ]
    content, used, usage = (chat_fn or _glm_chat)(messages, model, temperature)
    return strip_fence(content).strip(), used, usage


VC_EXPLAIN_SYSTEM = """Explain one OpenJML verification-condition failure to a Java developer.
Use at most three short sentences: what could happen, what fact is missing, and one sound next step.
Do not claim the suggested change is correct without human review. Return plain text only."""


def explain_vc_with_llm(category, detail, source_line="", model=None, chat_fn=None):
    messages = [{"role": "system", "content": VC_EXPLAIN_SYSTEM},
                {"role": "user", "content":
                 f"Category: {category}\nDiagnostic: {detail}\nSource line: {source_line}"}]
    content, used, usage = (chat_fn or _glm_chat)(messages, model, 0.0)
    return strip_fence(content).strip(), used, usage


# --- LLM judge (eval harness) ----------------------------------------------
JUDGE_SYSTEM = """You are a JML specification reviewer. Given a natural-language requirement, a GOLD reference JML spec, and a CANDIDATE JML spec, judge whether the candidate captures the same contracts (preconditions, postconditions, invariants) as the GOLD, modulo identifier naming and equivalent phrasing.

Return ONLY a ```json block:
{"score": <float 0.0-1.0>, "verdict": "equivalent" | "partial" | "wrong", "missing": [...], "extra_or_wrong": [...]}

Scoring:
- 1.0 = every gold contract is present and correct in the candidate (names may differ).
- 0.5 = some gold contracts missing, or a contract has the wrong bound/operator.
- 0.0 = most or all gold contracts are missing.
Put missing gold contracts in "missing"; put candidate contracts that are wrong or spurious in "extra_or_wrong"."""


def glm_judge(gold_stub, candidate_stub, nl, model=None, temperature=0.0):
    """LLM-judge semantic equivalence of a candidate JML spec vs gold, given the NL.

    Returns {score, verdict, missing, extra_or_wrong}. Never raises — on any failure
    returns verdict='error' so the eval keeps running.
    """
    if not candidate_stub.strip():
        return {"score": 0.0, "verdict": "wrong", "missing": ["(candidate empty)"], "extra_or_wrong": []}
    messages = [
        {"role": "system", "content": JUDGE_SYSTEM},
        {"role": "user", "content":
         "Requirement:\n" + nl + "\n\n"
         "GOLD spec:\n```java\n" + gold_stub + "\n```\n\n"
         "CANDIDATE spec:\n```java\n" + candidate_stub + "\n```\n\n"
         "Judge the candidate against the gold. Return only the ```json block."},
    ]
    try:
        content, _used, _usage = _glm_chat(messages, model, temperature)
    except LLMError as e:
        return {"score": 0.0, "verdict": "error",
                "missing": [f"judge failed: [{e.code}] {e.message}"], "extra_or_wrong": []}
    jsm = _JSON_FENCE.search(content)
    meta = _first_json_object(jsm.group(1) if jsm else content)
    try:
        score = float(meta.get("score", 0.0) or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return {
        "score": score,
        "verdict": meta.get("verdict", "unknown"),
        "missing": list(meta.get("missing") or []),
        "extra_or_wrong": list(meta.get("extra_or_wrong") or []),
    }


# --- Refine (patch/merge: no-clobber of human edits) -----------------------
REFINE_SYSTEM = SYSTEM + """

REFINE MODE: you are given the CURRENT JML stub, a refinement INSTRUCTION from the human,
and a set of LOCKED clauses the human has marked authoritative. Update the stub to satisfy
the instruction.
- PRESERVE every LOCKED clause verbatim (same predicate) unless the instruction explicitly
  and necessarily requires changing it. Any locked clause you alter will be flagged as a
  CONFLICT for the human to approve.
- Make the MINIMAL change that satisfies the instruction; keep the rest of the contract intact.
- Emit the updated ```java and ```json blocks as usual."""


def glm_refine(current_stub, instruction, locked_clauses, nl=None, model=None, temperature=0.2, chat_fn=None):
    """Refine a stub per a human instruction, preserving locked clauses. The caller (refine())
    diffs the result and flags any locked clause that was altered as a conflict.
    Returns (SpecDraft, model_used, usage). chat_fn selects the provider (default GLM).
    """
    locked = locked_clauses or []
    user = ("CURRENT JML stub:\n```java\n" + current_stub + "\n```\n\n"
            "Refinement instruction from the human:\n" + instruction + "\n\n")
    if nl:
        user += "Original natural-language requirement (for context):\n" + nl + "\n\n"
    if locked:
        user += ("LOCKED clauses the human marked authoritative — preserve verbatim unless "
                 "the instruction forces a change:\n"
                 + "\n".join("  - " + c for c in locked) + "\n\n")
    user += "Emit the updated ```java and ```json blocks."
    messages = [{"role": "system", "content": REFINE_SYSTEM + prompt_guardrails((nl or "") + "\n" + current_stub)},
                {"role": "user", "content": user}]
    content, used, usage = (chat_fn or _glm_chat)(messages, model, temperature)
    return _parse_draft(content), used, usage
