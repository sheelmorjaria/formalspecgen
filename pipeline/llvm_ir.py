# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""LLVM IR (.ll) module parsing and state-machine transition extraction.

M32: the scale lane. Instead of preprocessing and parsing source text, the
analyzer accepts ``clang -S -emit-llvm`` output and extracts V2 transitions
from the IR control-flow graph. The dialect was fixed by probing real clang
18 -O0 output BEFORE this module was written — a C ``switch (c->st)`` lowers
to a load of the field, a ``switch i32`` dispatch, and per-case basic blocks
that store constants back through the same ``getelementptr`` chain; guarded
cases lower to conditional branches whose arms each store, which is exactly
the source-level switch dialect's semantics one level down.

No llvmlite dependency: .ll is parsed as (very regular) text, fail-closed on
anything outside the dialect.
"""
from __future__ import annotations

import re
from pathlib import Path

try:  # Optional: real LLVM parsing when llvmlite is installed; the text
    # dialect below remains the deterministic fallback (tree-sitter pattern).
    import llvmlite.binding as _llvm
except ImportError:  # pragma: no cover - minimal environments
    _llvm = None

_DEFINE = re.compile(
    r"^define\s+(?P<header>[^@]+)@(?P<name>[\w.$-]+)\s*\(", re.M)
_LABEL = re.compile(r"^(?P<label>[\w.$-]+):\s*(?:;.*)?$", re.M)
_GEP = re.compile(
    r"=\s*getelementptr\s+inbounds\s+%struct\.(?P<struct>\w+),\s*"
    r"ptr\s+(?P<base>%[\w.$-]+),\s*i32\s+0,\s*i32\s+(?P<index>\d+)")
_LOAD_FIELD = re.compile(r"=\s*load\s+i32,\s*ptr\s+(?P<ptr>%[\w.$-]+)")
_STORE_CONST = re.compile(
    r"store\s+i32\s+(?P<value>-?\d+),\s*ptr\s+(?P<ptr>%[\w.$-]+)")
_BR = re.compile(r"^br\s+label\s+%(?P<target>[\w.$-]+)\s*$")
_BR_COND = re.compile(
    r"^br\s+i1\s+%[\w.$-]+,\s*label\s+%(?P<true>[\w.$-]+),\s*"
    r"label\s+%(?P<false>[\w.$-]+)\s*$")
_SWITCH_HEAD = re.compile(
    r"^switch\s+i32\s+(?P<operand>%[\w.$-]+),\s*label\s+%(?P<default>[\w.$-]+)\s*\[")
_SWITCH_CASE = re.compile(r"i32\s+(?P<value>-?\d+),\s*label\s+%(?P<target>[\w.$-]+)")


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message}


def parse_llvm_ir(text: str) -> dict:
    """Split a .ll module into functions and labeled basic blocks."""
    if _llvm is not None:
        try:
            _llvm.parse_assembly(text)
        except Exception as exc:   # llvmlite raises RuntimeError subclasses
            return _fail("ir_parse_error",
                         f"llvmlite rejected the module: {exc}")
    functions = []
    for header in _DEFINE.finditer(text):
        opening = text.find("{", header.start())
        if opening < 0:
            return _fail("ir_parse_error", "define without an opening brace")
        depth, index = 1, opening + 1
        while index < len(text) and depth:
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
            index += 1
        body = text[opening + 1:index - 1]
        blocks, current = [], None
        for line in body.splitlines():
            stripped = line.strip()
            label = _LABEL.match(stripped)
            if label is not None:
                current = {"label": label.group("label"), "lines": []}
                blocks.append(current)
                continue
            if not stripped or stripped.startswith(";"):
                continue
            if current is None:
                current = {"label": "entry", "lines": []}
                blocks.append(current)
            current["lines"].append(stripped)
        functions.append({"name": header.group("name"),
                          "header": header.group("header"),
                          "blocks": blocks})
    if not functions:
        return _fail("no_functions", "the module defines no functions")
    return {"status": "PARSED", "functions": functions}


def function_cfg(function: dict) -> dict:
    """Basic-block successors from each block's terminator."""
    labels = {block["label"] for block in function["blocks"]}
    edges = {}
    for block in function["blocks"]:
        successors = []
        for line in block["lines"]:
            conditional = _BR_COND.match(line)
            if conditional is not None:
                successors += [conditional.group("true"),
                               conditional.group("false")]
                continue
            unconditional = _BR.match(line)
            if unconditional is not None:
                successors.append(unconditional.group("target"))
                continue
            switch = _SWITCH_HEAD.match(line)
            if switch is not None:
                successors.append(switch.group("default"))
        # Multi-line switch cases are not terminator lines; collect them by
        # scanning the block for case rows that follow a switch head.
        in_switch = False
        for line in block["lines"]:
            if _SWITCH_HEAD.match(line) is not None:
                in_switch = True
                continue
            if in_switch:
                if line.strip() == "]":
                    in_switch = False
                    continue
                for case in _SWITCH_CASE.finditer(line):
                    successors.append(case.group("target"))
        edges[block["label"]] = [target for target in successors
                                 if target in labels]
    return {"entry": function["blocks"][0]["label"], "edges": edges}


def find_switches(function: dict) -> list[dict]:
    """Every ``switch i32`` dispatch with its case table."""
    switches = []
    for block in function["blocks"]:
        in_switch = False
        current = None
        for line in block["lines"]:
            head = _SWITCH_HEAD.match(line)
            if head is not None:
                current = {"block": block["label"],
                           "operand": head.group("operand"),
                           "default": head.group("default"), "cases": []}
                in_switch = True
                continue
            if in_switch:
                if line.strip() == "]":
                    switches.append(current)
                    in_switch, current = False, None
                    continue
                for case in _SWITCH_CASE.finditer(line):
                    current["cases"].append(
                        {"value": int(case.group("value")),
                         "target": case.group("target")})
    return switches


def _register_definition(function: dict, register: str):
    """The line that defines ``register`` (``%7 = load ...``), or None."""
    prefix = f"{register} =" if register.startswith("%") else f"%{register} ="
    for block in function["blocks"]:
        for line in block["lines"]:
            if line.startswith(prefix):
                return line
    return None


def _trace_field(function: dict, ptr_register: str) -> tuple[str, int] | None:
    """ptr -> (struct name, field index) through the getelementptr chain."""
    definition = _register_definition(function, ptr_register)
    if definition is None:
        return None
    gep = _GEP.search(definition)
    if gep is None:
        return None
    base = gep.group("base")
    base_definition = _register_definition(function, base)
    if base_definition is None or "load ptr" not in base_definition:
        return None
    return (gep.group("struct"), int(gep.group("index")))


def extract_ir_transitions(function: dict, notes: list[str] | None = None):
    """V2 transitions from one function's switch dispatches.

    Admitted shape (mirrors the source-level switch dialect): a switch whose
    operand loads a struct field, with case blocks (or their branch arms)
    storing integer constants back into the SAME field. Every
    (case value, stored constant) pair is one transition; guarded cases
    naturally yield one transition per arm. Everything else is skipped with
    a note for the reviewer.
    """
    notes = [] if notes is None else notes
    cfg = function_cfg(function)
    transitions = []
    for switch in find_switches(function):
        operand_definition = _register_definition(function, switch["operand"])
        load = _LOAD_FIELD.search(operand_definition or "")
        if load is None:
            notes.append(f"{function['name']}: switch operand "
                         f"{switch['operand']} is not a struct-field load; "
                         "skipped")
            continue
        field = _trace_field(function, load.group("ptr"))
        if field is None:
            notes.append(f"{function['name']}: switch operand does not trace "
                         "to a getelementptr struct field; skipped")
            continue
        field_name = f"{field[0]}_f{field[1]}"
        for case in switch["cases"]:
            stored = _stores_reachable(function, cfg, case["target"], field)
            if not stored:
                notes.append(f"{function['name']} case {case['value']}: "
                             "no constant store to the field reachable; "
                             "no transition")
                continue
            for value in sorted(stored):
                transitions.append({
                    "name": f"{function['name']}_{case['value']}_{value}",
                    "case": case["value"], "field": field_name,
                    "value": value})
    return transitions, notes


def _stores_reachable(function: dict, cfg: dict, start: str,
                      field: tuple[str, int]) -> set[int]:
    """Constants stored to ``field`` on any path from ``start`` (bounded)."""
    stored: set[int] = set()
    visited: set[str] = set()
    queue = [start]
    while queue and len(visited) <= len(cfg["edges"]):
        label = queue.pop()
        if label in visited:
            continue
        visited.add(label)
        block = next((b for b in function["blocks"] if b["label"] == label),
                     None)
        if block is None:
            continue
        for line in block["lines"]:
            store = _STORE_CONST.match(line)
            if store is None:
                continue
            target_field = _trace_field(function, store.group("ptr"))
            if target_field == field:
                stored.add(int(store.group("value")))
        queue.extend(cfg["edges"].get(label, []))
    return stored


def ir_cfg_correspondence(transitions: list[dict], module_text: str) -> dict:
    """Deterministic structural correspondence: every IR case-store of the
    modeled field is a modeled transition, and every modeled transition
    traces back to one.

    This is a structural check, deliberately NOT a solver claim: graph
    correspondence between a dispatch table and a transition list is
    decidable deterministically, and dressing it up as a Z3 obligation would
    misstate what was checked. Model-level proof stays with TLC/traverser.
    """
    module = parse_llvm_ir(module_text)
    if module.get("status") != "PARSED":
        return module
    expected = set()
    for function in module["functions"]:
        extracted, _ = extract_ir_transitions(function)
        expected |= {(item["field"], item["case"], item["value"])
                     for item in extracted}
    modeled = {(item["field"], item["case"], item["value"])
               for item in transitions}
    if not modeled and not expected:
        return _fail("no_machine_extracted",
                     "neither the IR nor the candidate contains transitions")
    missing = expected - modeled
    if missing:
        return _fail("cfg_transition_missing",
                     f"IR case-stores absent from the model: {sorted(missing)}")
    extra = modeled - expected
    if extra:
        return _fail("model_transition_untraced",
                     f"model transitions absent from the IR: {sorted(extra)}")
    return {"status": "CORRESPONDENCE_PROVED", "claim": "NO_PROOF",
            "scope": "deterministic_ir_cfg_structural_correspondence",
            "correspondence_proved": True, "transitions": len(expected)}
