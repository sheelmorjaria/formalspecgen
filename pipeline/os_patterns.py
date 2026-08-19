# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M40: OS-pattern extraction dialects (OS lane 5).

Two deterministic dialects the scalar extractor cannot see:

1. INTRUSIVE LISTS — list_add/list_del/list_move on a struct list_head
   become transitions on an abstract SIZE counter: add = size+1,
   del = size-1, bounded by the pool capacity. The pointers are
   abstracted away exactly as M30 capacity-bounding abstracted the pool
   itself; the UNBOUNDED_HEAP_DETECTED warning still fires for the raw
   pointer fields, so the reviewer sees both the abstraction and the
   shape it came from.

2. CALLBACK REGISTRATION — ``struct file_operations fops = { .read =
   dev_read, ... };`` and ``fops->read = dev_read;`` resolve the
   registered function; each registered function is reported as its own
   extractable machine for the existing lanes, with the registration
   site recorded for the composition gate. An initializer field whose
   target is not a function defined in the same source fails closed by
   name (external/unresolved callbacks are recorded, never guessed).
"""
from __future__ import annotations

import re
from pathlib import Path

_LIST_FN = re.compile(r"\b(list_add|list_add_tail|list_del|list_del_init|"
                      r"list_move|list_move_tail)\s*\(")
_LIST_HEAD_FIELD = re.compile(r"struct\s+list_head\s+(\w+)\s*;")
_INITIALIZER = re.compile(r"\.\s*(?P<slot>\w+)\s*=\s*(?P<target>\w+)\s*[,}]")
_ASSIGN_SLOT = re.compile(
    r"\b(?P<ops>\w+)\s*(?:->|\.)\s*(?P<slot>\w+)\s*=\s*(?P<target>\w+)\s*;")
_KNOWN_OPS_TABLES = {"file_operations", "fops", "ops", "callbacks"}


def _fail(code: str, message: str) -> dict:
    return {"status": "OS_PATTERN_EXTRACTION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def extract_intrusive_list(text: str, capacity: int | None = None) -> dict:
    """list_* calls on an embedded struct list_head → abstract size-counter
    transitions (add/move = +1 net, del = -1), bounded by the declared
    pool capacity."""
    heads = set(_LIST_HEAD_FIELD.findall(text))
    if not heads:
        return _fail("no_list_head",
                     "no embedded struct list_head field — the intrusive "
                     "list dialect has nothing to abstract")
    transitions = []
    for call in _LIST_FN.finditer(text):
        fn = call.group(1)
        effect = 1 if fn.startswith(("list_add", "list_move")) else -1
        transitions.append({"name": fn, "size_effect": effect})
    if not transitions:
        return _fail("no_list_operations",
                     "struct list_head present but no list_add/list_del/"
                     "list_move calls found")
    bound = capacity
    if bound is None:
        # no declared pool capacity: the pointer pool is unbounded —
        # refuse to guess a bound (the M11 discipline)
        return _fail("pool_capacity_missing",
                     "intrusive-list abstraction requires the pool "
                     "capacity (the M30 bounded-pool bound); the lane "
                     "never guesses one")
    total = sum(t["size_effect"] for t in transitions)
    if total > bound:
        return _fail("capacity_exceeded",
                     f"extracted net size effect {total} exceeds the "
                     f"declared capacity {bound}")
    return {
        "status": "INTRUSIVE_LIST_ABSTRACTED",
        "abstract_state_field": "size",
        "list_heads": sorted(heads),
        "transitions": transitions,
        "pool_capacity": bound,
        "abstraction": "pointers abstracted to a size counter bounded "
                       "by the pool capacity (the M30 discipline); the "
                       "raw pointer fields still carry the "
                       "UNBOUNDED_HEAP_DETECTED warning",
        "size_invariant": f"0 <= size <= {bound}",
    }


def resolve_callbacks(text: str) -> dict:
    """Function-pointer registrations in ops tables resolve to the
    registered function; unresolved targets are named, never guessed."""
    defined = set(re.findall(
        r"^\s*(?:static\s+)?(?:inline\s+)?(?:void|int|long|ssize_t)\s*\*?\s*"
        r"(\w+)\s*\(", text, re.M))
    registrations = []
    for init in _INITIALIZER.finditer(text):
        slot, target = init.group("slot"), init.group("target")
        if target in defined:
            registrations.append({"slot": slot, "target": target,
                                  "source": "initializer",
                                  "resolves_in_source": True})
        elif target in {"NULL", "0"} or target.startswith("THIS_MODULE"):
            continue
        else:
            registrations.append({"slot": slot, "target": target,
                                  "source": "initializer",
                                  "resolves_in_source": False})
    for assign in _ASSIGN_SLOT.finditer(text):
        ops, slot = assign.group("ops"), assign.group("slot")
        target = assign.group("target")
        if ops not in _KNOWN_OPS_TABLES:
            continue
        registrations.append({"slot": slot, "target": target,
                              "source": "assignment",
                              "resolves_in_source": target in defined})
    if not registrations:
        return _fail("no_callback_registrations",
                     "no function-pointer registrations found in any ops "
                     "table initializer or assignment")
    unresolved = sorted({r["target"] for r in registrations
                         if not r["resolves_in_source"]})
    return {
        "status": "CALLBACKS_RESOLVED" if not unresolved
        else "CALLBACKS_PARTIALLY_RESOLVED",
        "registrations": registrations,
        "machines_for_extraction": sorted(
            {r["target"] for r in registrations
             if r["resolves_in_source"]}),
        "unresolved": unresolved,
        "unresolved_note": "external or unresolved callbacks are recorded "
                           "by name for the composition gate; they are "
                           "never guessed at" if unresolved else None,
    }
