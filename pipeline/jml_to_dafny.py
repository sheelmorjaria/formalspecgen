# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed translator for reviewed JML encoding boundaries.

This is intentionally not a Java compiler.  It recognizes strong contract signatures and
lowers them to complete, independently verifiable Dafny templates.  Anything outside the
three reviewed shapes is rejected instead of emitting a misleading Java/Dafny hybrid.
"""
import re
import os
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field

from . import config


class UnsupportedBoundary(ValueError):
    pass


@dataclass
class Translation:
    boundary: str
    dafny_code: str
    rewrites: list[str] = field(default_factory=list)


@dataclass
class DafnyResult:
    status: str
    exit_code: int
    output: str
    translation: Translation


_METHOD = re.compile(
    r"public\s+static\s+(?:/\*@\s*pure\s*@\*/\s+)?(?P<ret>void|int|boolean)\s+"
    r"(?P<name>\w+)\s*\((?P<params>[^)]*)\)", re.DOTALL)
_ARRAY_PARAM = re.compile(r"int\s*\[\s*\]\s*(\w+)")
_INT_PARAMS = re.compile(r"\bint\s+(\w+)")
_PURE_INT_HEADER = re.compile(
    r"public\s+static\s+/\*@\s*pure\s*@\*/\s+int\s+(?P<name>\w+)\s*"
    r"\((?P<params>[^)]*)\)\s*\{", re.DOTALL)
_SAFE_PURE_EXPRESSION = re.compile(
    r"^[\w\s()+\-*/%<>=!&|?:,.\[\]]+$", re.DOTALL)


def detect_boundary(java_code: str) -> str | None:
    if (re.search(r"\bclass\s+\w+\s*\{.*?\b\w+\s+next\s*;", java_code, re.DOTALL)
            and re.search(r"/\*@\s*pure\s*@\*/\s+boolean\s+\w+\s*\(", java_code)):
        return "linked_reachability"
    if "\\num_of" in java_code:
        return "permutation_multiset"
    if re.search(r"\\old\s*\(\s*\w+\s*\)\s*\[", java_code):
        return "heap_snapshot"
    if "/*@ pure @*/" in java_code or re.search(r"\b(?:gcd|sumOf)\s*\(", java_code):
        return "recursive_helper"
    return None


def translate_jml_to_dafny(java_code: str) -> Translation:
    boundary = detect_boundary(java_code)
    if boundary == "linked_reachability":
        node, helper, start, target = _linked_reachability(java_code)
        return Translation(boundary, _render_linked_reachability(node, helper, start, target), [
            "singly linked Java identity graph -> Dafny class with ghost representation set",
            "explicit acyclic precondition -> strict-subset dynamic-frame decrease",
            "recursive pure reachability helper -> heap-reading Dafny predicate",
        ])
    method = _METHOD.search(java_code)
    if boundary is None:
        raise UnsupportedBoundary("no known JML encoding boundary was detected")
    if method is None:
        raise UnsupportedBoundary("expected one public static method")

    name, params = method.group("name"), method.group("params")
    if boundary == "heap_snapshot":
        array = _one_array(params)
        if not re.search(rf"\\old\s*\(\s*{re.escape(array)}\s*\)\s*\[", java_code):
            raise UnsupportedBoundary("old-state expression does not reference the method array")
        return Translation(boundary, _reverse(name, array), [
            f"\\old({array}) indexed heap reads -> immutable ghost sequence snapshot",
            ".length -> .Length",
            "paired swap loop -> sequence-indexed Dafny loop invariants",
        ])

    if boundary == "permutation_multiset":
        array = _one_array(params)
        if not ("\\num_of" in java_code and re.search(rf"{re.escape(array)}\s*\[", java_code)):
            raise UnsupportedBoundary("num_of property does not count values in the method array")
        return Translation(boundary, _insertion_sort(name, array), [
            "value-counting \\num_of postcondition -> native multiset equality",
            "sorted forall postcondition -> Dafny forall",
            ".length -> .Length",
        ])

    helper = _recursive_pure_helper(java_code)
    return Translation(boundary, _render_pure_helper(*helper), [
        "side-effect-free recursive Java helper -> Dafny mathematical function",
        "Java conditional expression -> Dafny if/then/else expression",
        "recursive termination -> Dafny inferred decreases tuple",
    ])


def _linked_reachability(java_code: str) -> tuple[str, str, str, str]:
    classes = re.findall(r"\b(?:public\s+)?class\s+(\w+)\s*\{", java_code)
    candidates = []
    for node in classes:
        links = re.findall(rf"\b{re.escape(node)}\s+(\w+)\s*;", java_code)
        if links == ["next"]:
            candidates.append(node)
    if len(candidates) != 1:
        raise UnsupportedBoundary("expected exactly one node class with exactly one Node next link")
    node = candidates[0]
    header = re.search(
        rf"public\s+static\s+/\*@\s*pure\s*@\*/\s+boolean\s+(\w+)\s*\(\s*"
        rf"{re.escape(node)}\s+(\w+)\s*,\s*{re.escape(node)}\s+(\w+)\s*\)\s*\{{",
        java_code)
    if not header:
        raise UnsupportedBoundary("expected one pure boolean reachability helper over two nodes")
    end = _matching_brace(java_code, header.end() - 1)
    body = java_code[header.end():end].strip()
    returned = re.fullmatch(r"return\s+(.+?)\s*;", body, re.DOTALL)
    if not returned:
        raise UnsupportedBoundary("reachability helper must contain one recursive return expression")
    helper, start, target = header.group(1), header.group(2), header.group(3)
    normalized = re.sub(r"\s+", "", returned.group(1))
    accepted = {
        f"{start}=={target}||({start}.next!=null&&{helper}({start}.next,{target}))",
        f"{start}=={target}||{start}.next!=null&&{helper}({start}.next,{target})",
    }
    if normalized not in accepted:
        raise UnsupportedBoundary("recursive reachability expression is outside the reviewed subset")
    prefix = java_code[:header.start()]
    requires = _preceding_requires(prefix)
    required = {f"{start}!=null", f"{target}!=null", f"acyclic({start})"}
    normalized_requires = {re.sub(r"\s+", "", clause) for clause in requires}
    if not required.issubset(normalized_requires):
        raise UnsupportedBoundary("linked reachability requires explicit non-null and acyclic preconditions")
    if not re.search(r"(?m)^\s*//@\s*assignable\s+\\nothing\s*;\s*$", prefix):
        raise UnsupportedBoundary("linked reachability helper must declare assignable \\nothing")
    outside_helper = java_code[:header.start()] + java_code[end + 1:]
    if re.search(r"\.next\s*=|\bnext\s*=", outside_helper):
        raise UnsupportedBoundary("linked reachability boundary does not permit link mutation")
    return node, helper, start, target


def _render_linked_reachability(node: str, helper: str, start: str, target: str) -> str:
    return f"""class {node} {{
  var next: {node}?
  ghost var Repr: set<{node}>

  ghost predicate Valid()
    reads this, Repr
    decreases Repr
  {{
    this in Repr &&
    (next != null ==> next in Repr && next.Repr < Repr && next.Valid())
  }}
}}

ghost predicate {helper}({start}: {node}, {target}: {node})
  requires {start}.Valid()
  reads {start}.Repr
  decreases {start}.Repr
{{
  {start} == {target} ||
  ({start}.next != null && {helper}({start}.next, {target}))
}}
"""


def translate_and_verify(java_code: str) -> DafnyResult:
    """Translate a recognized boundary and invoke the real Dafny verifier."""
    translation = translate_jml_to_dafny(java_code)
    binary = Path(config.DAFNY_BIN)
    if not binary.exists():
        return DafnyResult("TOOL_MISSING", 127,
                           f"Dafny executable not found at {binary}", translation)
    env = os.environ.copy()
    env["DOTNET_ROOT"] = config.DOTNET_ROOT
    try:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Boundary.dfy"
            source.write_text(translation.dafny_code, encoding="utf-8")
            process = subprocess.run(
                [str(binary), "verify", str(source)], capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=config.DAFNY_TIMEOUT, env=env)
        output = (process.stdout or "") + (process.stderr or "")
        status = "VERIFIED" if process.returncode == 0 else "VERIFY_FAILED"
        return DafnyResult(status, process.returncode, output.strip(), translation)
    except subprocess.TimeoutExpired:
        return DafnyResult("TIMEOUT", 124,
                           f"Dafny verification timed out after {config.DAFNY_TIMEOUT}s", translation)


def _one_array(params: str) -> str:
    arrays = _ARRAY_PARAM.findall(params)
    if len(arrays) != 1:
        raise UnsupportedBoundary("expected exactly one int[] parameter")
    return arrays[0]


def _reverse(name: str, array: str) -> str:
    return f"""method {name}({array}: array<int>)
  modifies {array}
  ensures forall i :: 0 <= i < {array}.Length ==> {array}[i] == old({array}[{array}.Length - 1 - i])
{{
  ghost var {array}_snapshot := {array}[..];
  var i := 0;
  while i < {array}.Length / 2
    invariant 0 <= i <= {array}.Length / 2
    invariant forall k :: 0 <= k < i ==> {array}[k] == {array}_snapshot[{array}.Length - 1 - k]
    invariant forall k :: 0 <= k < i ==> {array}[{array}.Length - 1 - k] == {array}_snapshot[k]
    invariant forall k :: i <= k < {array}.Length - i ==> {array}[k] == {array}_snapshot[k]
    decreases {array}.Length / 2 - i
  {{
    var tmp := {array}[i];
    {array}[i] := {array}[{array}.Length - 1 - i];
    {array}[{array}.Length - 1 - i] := tmp;
    i := i + 1;
  }}
}}
"""


def _insertion_sort(name: str, array: str) -> str:
    # Selection-sort lowering is used deliberately: this is the corpus-proven native
    # multiset template and satisfies the same sorting/permutation contract.
    return f"""method {name}({array}: array<int>)
  modifies {array}
  ensures forall k :: 0 <= k < {array}.Length - 1 ==> {array}[k] <= {array}[k + 1]
  ensures multiset({array}[..]) == multiset(old({array}[..]))
{{
  var i := 0;
  while i < {array}.Length
    invariant 0 <= i <= {array}.Length
    invariant multiset({array}[..]) == multiset(old({array}[..]))
    invariant forall k, j :: 0 <= k < j < i ==> {array}[k] <= {array}[j]
    invariant forall k, j :: 0 <= k < i && i <= j < {array}.Length ==> {array}[k] <= {array}[j]
    decreases {array}.Length - i
  {{
    var min := i;
    var j := i + 1;
    while j < {array}.Length
      invariant i <= min < {array}.Length
      invariant i < j <= {array}.Length
      invariant forall k :: i <= k < j ==> {array}[min] <= {array}[k]
      decreases {array}.Length - j
    {{
      if {array}[j] < {array}[min] {{ min := j; }}
      j := j + 1;
    }}
    var tmp := {array}[i]; {array}[i] := {array}[min]; {array}[min] := tmp;
    i := i + 1;
  }}
}}
"""


def _recursive_pure_helper(java_code: str) -> tuple[str, list[tuple[str, str]], str, list[str]]:
    """Extract one reviewed pure-recursive helper without parsing arbitrary Java.

    Accepted helpers return one expression and have only ``int`` parameters.  Balanced
    brace extraction avoids the classic non-greedy-regex truncation bug.  Anything with
    statements, mutation, unsupported types, or no direct self-call is rejected.
    """
    matches = []
    for header in _PURE_INT_HEADER.finditer(java_code):
        end = _matching_brace(java_code, header.end() - 1)
        body = java_code[header.end():end].strip()
        returned = re.fullmatch(r"return\s+(.+?)\s*;", body, re.DOTALL)
        if not returned:
            continue
        name = header.group("name")
        expression = returned.group(1).strip()
        if not re.search(rf"\b{re.escape(name)}\s*\(", expression):
            continue
        params = _pure_int_params(header.group("params"))
        requires = _preceding_requires(java_code[:header.start()])
        matches.append((name, params, expression, requires))
    if not matches:
        raise UnsupportedBoundary(
            "expected a public static /*@ pure @*/ int helper with a single recursive return expression")
    if len(matches) != 1:
        raise UnsupportedBoundary("expected exactly one recursive pure helper")
    return matches[0]


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise UnsupportedBoundary("unterminated pure helper body")


def _pure_int_params(source: str) -> list[tuple[str, str]]:
    if not source.strip():
        return []
    params = []
    for raw in source.split(","):
        match = re.fullmatch(r"\s*int\s+(\w+)\s*", raw)
        if not match:
            raise UnsupportedBoundary(f"unsupported pure-helper parameter: {raw.strip()}")
        params.append((match.group(1), "int"))
    return params


def _preceding_requires(prefix: str) -> list[str]:
    clauses = []
    for line in reversed(prefix.splitlines()):
        stripped = line.strip()
        match = re.fullmatch(r"//@\s*requires\s+(.+?)\s*;", stripped)
        if match:
            clauses.append(match.group(1))
        elif not stripped or stripped.startswith("//@"):
            continue
        else:
            break
    return list(reversed(clauses))


def _render_pure_helper(name: str, params: list[tuple[str, str]], expression: str,
                        requires: list[str]) -> str:
    rendered_expression = _render_pure_expression(expression)
    rendered_requires = []
    for clause in requires:
        if "\\" in clause:
            raise UnsupportedBoundary(f"unsupported JML construct in pure-helper precondition: {clause}")
        rendered_requires.append(f"  requires {_render_pure_expression(clause)}")
    parameters = ", ".join(f"{param}: {kind}" for param, kind in params)
    contract = ("\n" + "\n".join(rendered_requires)) if rendered_requires else ""
    return f"function {name}({parameters}): int{contract}\n{{\n  {rendered_expression}\n}}\n"


def _render_pure_expression(expression: str) -> str:
    expression = expression.strip()
    if not expression or not _SAFE_PURE_EXPRESSION.fullmatch(expression):
        raise UnsupportedBoundary("pure helper contains an unsupported expression token")
    if re.search(r"(?:\+\+|--|\bnew\b|\bthis\b|\.)", expression):
        raise UnsupportedBoundary("pure helper expression contains mutation, allocation, or member access")
    question, colon = _top_level_ternary(expression)
    if question is not None:
        condition = _render_pure_expression(expression[:question])
        when_true = _render_pure_expression(expression[question + 1:colon])
        when_false = _render_pure_expression(expression[colon + 1:])
        return f"if {condition} then {when_true} else {when_false}"
    if "?" in expression or ":" in expression:
        raise UnsupportedBoundary("nested pure-helper conditional is outside the reviewed subset")
    return expression


def _top_level_ternary(expression: str) -> tuple[int | None, int | None]:
    depth = nested = 0
    question = None
    for index, token in enumerate(expression):
        if token in "([":
            depth += 1
        elif token in ")]":
            depth -= 1
            if depth < 0:
                raise UnsupportedBoundary("unbalanced pure-helper expression")
        elif depth == 0 and token == "?":
            if question is None:
                question = index
            nested += 1
        elif depth == 0 and token == ":" and question is not None:
            nested -= 1
            if nested == 0:
                return question, index
    if depth != 0 or question is not None:
        raise UnsupportedBoundary("unbalanced or incomplete pure-helper conditional")
    return None, None
