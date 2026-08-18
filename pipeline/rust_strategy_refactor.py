# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Narrow deterministic Strategy extraction for the Rust/Prusti lane.

Admitted shape (everything else fails closed): one ``pub fn name(&mut self,
kind: i32)`` whose body is solely a ``match kind { .. }`` where every arm
assigns the SAME int field one integer literal, with a required ``_``
catch-all arm, and a leading ``#[ensures(self.<field> >= <bound>)]`` whose
bound is at most the smallest arm literal.

The emitted shape is dictated by the prover, probed against real Prusti
0.2.2 before this module was written:
- trait-object dispatch (``&dyn`` in match arms, ``Box<dyn>``, even
  const-hoisted ``&dyn``) is REJECTED — creating a trait object is an
  unsupported loan-creating cast;
- ``#[ensures]`` on impl blocks is REJECTED (E0407: the desugared
  postcondition method is not a member of the trait);
- the verified shape is STATIC dispatch: the contract lives on the trait
  METHOD DECLARATION, one unit struct per arm, and a selecting enum whose
  apply forwards to them. Prusti verifies the whole file.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

_SIGNATURE = re.compile(
    r"^\s*pub\s+fn\s+(?P<name>\w+)\s*\(\s*&mut\s+self\s*,\s*"
    r"(?P<param>\w+)\s*:\s*i32\s*\)\s*$")
_ENSURES = re.compile(
    r"#\[ensures\(self\.(?P<field>\w+)\s*>=\s*(?P<bound>-?\d+)\)\]")
_MATCH_BODY = re.compile(
    r"^\s*match\s+(?P<scrutinee>\w+)\s*\{(?P<arms>.*)\}\s*$", re.S)
_ARM = re.compile(
    r"(?P<pattern>\d+|_)\s*=>\s*self\.(?P<field>\w+)\s*=\s*(?P<value>-?\d+)\s*,?")
_IMPL_LINE = re.compile(r"(?m)^(?P<indent>[ \t]*)impl\s+[\w:]")


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "formal_preservation_proved": False,
            "requires_refactor_gate": True}


def _pascal(snake: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in snake.split("_") if part)


def _line_indent(source: str, position: int) -> str:
    line_start = source.rfind("\n", 0, position) + 1
    return re.match(r"[ \t]*", source[line_start:]).group(0)


def extract_strategy_rust(source: str | Path, method: str) -> dict:
    """Transform one literal-dispatch match into the probed strategy shape."""
    from .polyglot_extract_method import locate_function
    if isinstance(source, Path) or ("\n" not in str(source) and
                                    str(source).endswith(".rs")):
        source = Path(source).read_text(encoding="utf-8")
    text = source
    located = locate_function(text, "rust", method)
    if located.get("status") != "LOCATED":
        return located          # fail-closed locator codes pass through
    fn_start, body_start, body_end = (located["function_start"],
                                      located["body_start"], located["body_end"])
    signature = text[fn_start:body_start]
    match = _SIGNATURE.match(signature.replace("\n", " "))
    if match is None or match.group("name") != method:
        return _fail("unsupported_method_shape",
                     "Strategy extraction requires pub fn name(&mut self, "
                     "kind: i32) — one i32 parameter, no return value")
    parameter = match.group("param")
    attributes = text[located["contract_start"]:fn_start]
    contract = _ENSURES.search(attributes)
    if contract is None:
        return _fail("strategy_contract_required",
                     "a leading #[ensures(self.<field> >= <bound>)] is required "
                     "so the trait method can carry the translated contract")
    body_match = _MATCH_BODY.match(text[body_start + 1:body_end - 1])
    if body_match is None or body_match.group("scrutinee") != parameter:
        return _fail("strategy_match_body_required",
                     "the method body must consist solely of a match on the "
                     "i32 parameter")
    arms = _ARM.findall(body_match.group("arms"))
    covered = "".join(hit.group(0) for hit in
                      _ARM.finditer(body_match.group("arms")))
    if (not arms or
            re.sub(r"\s+", "", covered) !=
            re.sub(r"\s+", "", body_match.group("arms"))):
        return _fail("strategy_arm_shape_required",
                     "every arm must assign one integer literal to a self field")
    patterns = [pattern for pattern, _, _ in arms]
    fields = {field for _, field, _ in arms}
    if len(fields) != 1:
        return _fail("strategy_single_field_required",
                     "every arm must assign the same state field")
    if patterns.count("_") != 1 or patterns[-1] != "_":
        return _fail("strategy_catchall_required",
                     "the match must end in exactly one _ catch-all arm")
    literals = [int(pattern) for pattern in patterns if pattern != "_"]
    if len(set(literals)) != len(literals):
        return _fail("strategy_distinct_patterns_required",
                     "literal arm patterns must be distinct")
    field = next(iter(fields))
    bound = int(contract.group("bound"))
    values = [int(value) for _, _, value in arms]
    if bound > min(values):
        return _fail("strategy_contract_not_established",
                     "the ensures bound exceeds an arm's literal, so the "
                     "baseline itself cannot satisfy the contract")

    impl_line = None
    for candidate in _IMPL_LINE.finditer(text):
        if candidate.start() < fn_start:
            impl_line = candidate
    if impl_line is None:
        return _fail("enclosing_impl_required",
                     "the method must live inside an impl block whose type "
                     "names the strategy target")
    impl_match = re.match(r"impl\s+([\w:]+)", text[impl_line.start() + len(impl_line.group("indent")):])
    owner = impl_match.group(1).split("::")[-1]

    trait = f"{_pascal(method)}Strategy"
    struct_names = [f"{trait}{index}" for index in range(1, len(literals) + 1)]
    fallback = f"{trait}Default"
    enum_name = f"Selected{trait}"
    selector = f"select_{method}"
    for name in [trait, *struct_names, fallback, enum_name, selector]:
        if re.search(rf"\b{name}\b", text):
            return _fail("name_collision",
                         f"identifier {name} already exists in the source")

    ensures = f"#[ensures(t.{field} >= {bound})]"
    lines = [f"pub trait {trait} {{",
             f"    {ensures}",
             f"    fn apply(&self, t: &mut {owner});",
             "}",
             ""]
    for name, value in zip(struct_names + [fallback], values):
        lines += [f"pub struct {name};", "",
                  f"impl {trait} for {name} {{",
                  f"    fn apply(&self, t: &mut {owner}) {{ t.{field} = {value}; }}",
                  "}", ""]
    variants = [f"Arm{index}({name})"
                for index, name in enumerate(struct_names + [fallback], 1)]
    lines += [f"enum {enum_name} {{ {', '.join(variants)} }}", "",
              f"impl {trait} for {enum_name} {{",
              "    fn apply(&self, t: &mut %s) {" % owner,
              "        match self {",
              *[f"            {enum_name}::Arm{index}(s) => s.apply(t),"
                for index in range(1, len(variants) + 1)],
              "        }",
              "    }",
              "}", "",
              f"fn {selector}({parameter}: i32) -> {enum_name} {{",
              "    match %s {" % parameter,
              *[f"        {pattern} => {enum_name}::Arm{index}({name}),"
                for index, (pattern, name) in enumerate(
                    zip(patterns, struct_names + [fallback]), 1)],
              "    }",
              "}",
              ""]
    block = "\n".join(lines)

    indent = _line_indent(text, fn_start)
    new_body = ("{\n" + indent + f"    {selector}({parameter}).apply(self);\n"
                + indent + "}")
    transformed = (text[:body_start] + new_body + text[body_end:])
    insertion = impl_line.start()
    transformed = (transformed[:insertion] + block + "\n"
                   + transformed[insertion:])
    digest = hashlib.sha256(text.encode()).hexdigest()
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_REFACTOR_CANDIDATE",
            "pattern": "Strategy (enum-dispatch, static polymorphism)",
            "method": method, "source_sha256": digest,
            "refactored_sha256": hashlib.sha256(transformed.encode()).hexdigest(),
            "source": transformed, "trait": trait, "enum": enum_name,
            "selector": selector, "formal_preservation_proved": False,
            "requires_refactor_gate": True,
            "note": "trait-object dispatch is unprovable on Prusti 0.2.2 "
                    "(loan-creating unsize casts); the probed static-dispatch "
                    "shape carries the contract on the trait method"}


def apply_strategy_rust(source: str | Path, method: str, out: str | Path) -> dict:
    """Transform, write the refactored file, and run the proof gate."""
    from .refactor_gate import verify_contract_preserving_refactor
    transformed = extract_strategy_rust(source, method)
    if transformed["status"] != "TRANSFORMED":
        return transformed
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(transformed.pop("source"), encoding="utf-8")
    proof = verify_contract_preserving_refactor(source, destination)
    return {"status": "VERIFIED" if proof["status"] == "VERIFIED" else "FAIL",
            "claim": proof.get("claim", "NO_PROOF"),
            "transformation": transformed, "verification": proof,
            "automated_refactor_applied": True,
            "behavior_equivalence_proved": False,
            "refactor_verified": False}
