# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic TLA+/CFG serialization for validated V2 bounded domains."""
from __future__ import annotations

from .domain_v2 import (
    BinaryExpr, BooleanExpr, BoolStateVariable, DomainSpecV2, FieldExpr,
    IntegerExpr, NotExpr, OldExpr,
)
from .domain_v2_model import UnsupportedV2Boundary

_OPS = {"eq":"=", "neq":"/=", "lt":"<", "lte":"<=", "gt":">", "gte":">=",
        "add":"+", "sub":"-", "implies":"=>", "and":"/\\", "or":"\\/"}


def render_expression(node) -> str:
    if isinstance(node, FieldExpr): return node.name
    if isinstance(node, IntegerExpr): return str(node.value)
    if isinstance(node, BooleanExpr): return "TRUE" if node.value else "FALSE"
    if isinstance(node, OldExpr): return render_expression(node.expression)
    if isinstance(node, NotExpr): return f"~({render_expression(node.expression)})"
    if isinstance(node, BinaryExpr):
        return f"({render_expression(node.left)} {_OPS[node.kind]} {render_expression(node.right)})"
    raise UnsupportedV2Boundary(f"unsupported expression node {type(node).__name__}")


def _unchanged(names: list[str]) -> list[str]:
    return [f"    /\\ UNCHANGED <<{', '.join(names)}>>"] if names else []


def _contains_negative_integer(value) -> bool:
    if isinstance(value, dict):
        if (value.get("kind") == "integer" and isinstance(value.get("value"), int) and
                value["value"] < 0):
            return True
        return any(_contains_negative_integer(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_negative_integer(item) for item in value)
    return False


def render_v2_tla(spec: DomainSpecV2) -> tuple[str, str]:
    if spec.concurrency is not None:
        metadata = spec.concurrency
        if (metadata.unlocked_value is None or metadata.actor_lock_values is None or
                metadata.linearization_points is None):
            raise UnsupportedV2Boundary(
                "lock_protocol requires per-actor invocation/response histories, program "
                "counters, ownership values, and reviewed linearization points")
        return _render_lock_protocol(spec)
    domain_vars = [item.name for item in spec.state_variables]
    boolean_ops = [item for item in spec.operations if item.return_type == "boolean"]
    if any(item.failure_semantics == "exception" for item in boolean_ops):
        raise UnsupportedV2Boundary("V2 exception-result TLA+ rendering is not reviewed")
    variables = domain_vars + (["callResult"] if boolean_ops else [])
    init = [f"    /\\ {item.name} = " +
            (("TRUE" if item.initial else "FALSE") if isinstance(item, BoolStateVariable)
             else str(item.initial)) for item in spec.state_variables]
    if boolean_ops:
        init.append('    /\\ callResult = [a \\in Actors |-> "none"]')
    typeok=[]
    for item in spec.state_variables:
        typeok.append(f"    /\\ {item.name} \\in " +
                      ("BOOLEAN" if isinstance(item, BoolStateVariable)
                       else f"{item.bound[0]}..{item.bound[1]}"))
    if boolean_ops:
        typeok.append('    /\\ callResult \\in [Actors -> {"none", "true", "false"}]')
    actions=[]; next_items=[]
    for operation in spec.operations:
        guards=[render_expression(item.expression) for item in operation.guards]
        guard=" /\\ ".join(guards) if guards else "TRUE"
        effects=[f"    /\\ {item.target}' = {render_expression(item.value)}"
                 for item in operation.effects]
        unchanged=[name for name in domain_vars if name not in operation.frame]
        if operation.return_type == "boolean":
            success=f"{operation.name}Success(actor) ==\n    /\\ actor \\in Actors\n    /\\ {guard}\n"
            success += '\n'.join(effects +
                ['    /\\ callResult\' = [callResult EXCEPT ![actor] = "true"]'] +
                _unchanged(unchanged))
            actions.append(success); next_items.append(
                f"    \\/ \\E actor \\in Actors : {operation.name}Success(actor)")
            if operation.failure_semantics == "false_and_stutter":
                failure=(f"{operation.name}Failure(actor) ==\n    /\\ actor \\in Actors\n"
                    f"    /\\ ~({guard})\n"
                    '    /\\ callResult\' = [callResult EXCEPT ![actor] = "false"]\n' +
                    '\n'.join(_unchanged(domain_vars)))
                actions.append(failure); next_items.append(
                    f"    \\/ \\E actor \\in Actors : {operation.name}Failure(actor)")
        else:
            action=f"{operation.name} ==\n    /\\ {guard}\n" + '\n'.join(
                effects + _unchanged(unchanged + (["callResult"] if boolean_ops else [])))
            actions.append(action); next_items.append(f"    \\/ {operation.name}")
    invariants='\n'.join(f"{item.id} == {render_expression(item.expression)}"
                         for item in spec.tlc_invariants)
    # Preserve canonical positive-only serialization while selecting Integers
    # when bounds, initial values, or expressions use a negative sentinel.
    needs_integers = any(
        not isinstance(item, BoolStateVariable) and
        (item.bound[0] < 0 or item.initial < 0)
        for item in spec.state_variables) or _contains_negative_integer(
            spec.model_dump(mode="json"))
    arithmetic_module = "Integers" if needs_integers else "Naturals"
    tla=(f"---- MODULE {spec.domain_name} ----\nEXTENDS {arithmetic_module}\n\n" +
         ("CONSTANTS Actors\n\n" if boolean_ops else "") +
         f"VARIABLES {', '.join(variables)}\nvars == <<{', '.join(variables)}>>\n\n" +
         "Init ==\n"+'\n'.join(init)+"\n\nTypeOK ==\n"+'\n'.join(typeok)+"\n\n"+
         '\n\n'.join(actions)+"\n\nNext ==\n"+'\n'.join(next_items)+"\n\n"+
         invariants+"\n\nSpec == Init /\\ [][Next]_vars\n====\n")
    cfg=((f"CONSTANTS\nActors = {{{', '.join(f'a{i+1}' for i in range(spec.actors))}}}\n\n"
          if boolean_ops else "") + "SPECIFICATION\nSpec\n\nINVARIANT\nTypeOK\n" +
         ''.join(f"\nINVARIANT\n{item.id}\n" for item in spec.tlc_invariants))
    return tla, cfg


def _render_lock_protocol(spec: DomainSpecV2) -> tuple[str, str]:
    """Render a bounded invocation/acquire/commit/release/response history."""
    metadata = spec.concurrency
    assert metadata is not None and metadata.actor_lock_values is not None
    assert metadata.unlocked_value is not None
    domain_vars = [item.name for item in spec.state_variables]
    lock = metadata.lock_variable
    variables = [*domain_vars, "pc", "pendingOp"]
    init = [f"    /\\ {item.name} = " +
            (str(item.initial) if not isinstance(item, BoolStateVariable) else
             ("TRUE" if item.initial else "FALSE"))
            for item in spec.state_variables]
    init.extend([
        '    /\\ pc = [a \\in Actors |-> "IDLE"]',
        '    /\\ pendingOp = [a \\in Actors |-> "none"]',
    ])
    typeok = []
    for item in spec.state_variables:
        typeok.append(f"    /\\ {item.name} \\in " +
                      ("BOOLEAN" if isinstance(item, BoolStateVariable)
                       else f"{item.bound[0]}..{item.bound[1]}"))
    operation_names = ", ".join(f'"{item.name}"' for item in spec.operations)
    typeok.extend([
        '    /\\ pc \\in [Actors -> {"IDLE", "INVOKED", "ACQUIRED", '
        '"LINEARIZED", "RELEASED"}]',
        f'    /\\ pendingOp \\in [Actors -> {{"none", {operation_names}}}]',
    ])
    owner_cases = " [] ".join(
        f"actor = {index + 1} -> {value}"
        for index, value in enumerate(metadata.actor_lock_values))
    actions = [f"OwnerValue(actor) == CASE {owner_cases}"]
    next_items = []
    for operation in spec.operations:
        guards = [render_expression(item.expression) for item in operation.guards]
        guard = " /\\ ".join(guards) if guards else "TRUE"
        effects = [f"    /\\ {item.target}' = {render_expression(item.value)}"
                   for item in operation.effects]
        commit_unchanged = [name for name in domain_vars if name not in operation.frame]
        acquire_unchanged = ["pendingOp", *(
            name for name in domain_vars if name != lock)]
        release_unchanged = acquire_unchanged
        prefix = operation.name
        actions.extend([
            f'{prefix}Invoke(actor) ==\n    /\\ actor \\in Actors\n'
            f'    /\\ pc[actor] = "IDLE"\n'
            f'    /\\ pc\' = [pc EXCEPT ![actor] = "INVOKED"]\n'
            f'    /\\ pendingOp\' = [pendingOp EXCEPT ![actor] = "{operation.name}"]\n'
            f'    /\\ UNCHANGED <<{", ".join(domain_vars)}>>',
            f'{prefix}Acquire(actor) ==\n    /\\ actor \\in Actors\n'
            f'    /\\ pc[actor] = "INVOKED"\n'
            f'    /\\ pendingOp[actor] = "{operation.name}"\n'
            f'    /\\ {lock} = {metadata.unlocked_value}\n'
            f'    /\\ {lock}\' = OwnerValue(actor)\n'
            f'    /\\ pc\' = [pc EXCEPT ![actor] = "ACQUIRED"]\n'
            f'    /\\ UNCHANGED <<{", ".join(acquire_unchanged)}>>',
            f'{prefix}Linearize(actor) ==\n    /\\ actor \\in Actors\n'
            f'    /\\ pc[actor] = "ACQUIRED"\n'
            f'    /\\ pendingOp[actor] = "{operation.name}"\n'
            f'    /\\ {lock} = OwnerValue(actor)\n    /\\ {guard}\n' + "\n".join(effects) + "\n" +
            f'    /\\ pc\' = [pc EXCEPT ![actor] = "LINEARIZED"]\n'
            f'    /\\ UNCHANGED <<pendingOp, {", ".join(commit_unchanged)}>>',
            f'{prefix}Reject(actor) ==\n    /\\ actor \\in Actors\n'
            f'    /\\ pc[actor] = "ACQUIRED"\n'
            f'    /\\ pendingOp[actor] = "{operation.name}"\n'
            f'    /\\ {lock} = OwnerValue(actor)\n    /\\ ~({guard})\n'
            f'    /\\ {lock}\' = {metadata.unlocked_value}\n'
            f'    /\\ pc\' = [pc EXCEPT ![actor] = "RELEASED"]\n'
            f'    /\\ UNCHANGED <<{", ".join(release_unchanged)}>>',
            f'{prefix}Release(actor) ==\n    /\\ actor \\in Actors\n'
            f'    /\\ pc[actor] = "LINEARIZED"\n'
            f'    /\\ {lock} = OwnerValue(actor)\n'
            f'    /\\ {lock}\' = {metadata.unlocked_value}\n'
            f'    /\\ pc\' = [pc EXCEPT ![actor] = "RELEASED"]\n'
            f'    /\\ UNCHANGED <<{", ".join(release_unchanged)}>>',
            f'{prefix}Respond(actor) ==\n    /\\ actor \\in Actors\n'
            f'    /\\ pc[actor] = "RELEASED"\n'
            f'    /\\ pc\' = [pc EXCEPT ![actor] = "IDLE"]\n'
            f'    /\\ pendingOp\' = [pendingOp EXCEPT ![actor] = "none"]\n'
            f'    /\\ UNCHANGED <<{", ".join(domain_vars)}>>',
        ])
        next_items.extend(
            f"    \\/ \\E actor \\in Actors : {prefix}{phase}(actor)"
            for phase in ("Invoke", "Acquire", "Linearize", "Reject", "Release", "Respond"))
    invariants = "\n".join(
        f"{item.id} == {render_expression(item.expression)}"
        for item in spec.tlc_invariants)
    tla = (f"---- MODULE {spec.domain_name} ----\nEXTENDS Integers\n\n"
           f"Actors == 1..{spec.actors}\n\n" +
           f"VARIABLES {', '.join(variables)}\nvars == <<{', '.join(variables)}>>\n\n"
           "Init ==\n" + "\n".join(init) + "\n\nTypeOK ==\n" + "\n".join(typeok) +
           "\n\n" + "\n\n".join(actions) + "\n\nNext ==\n" + "\n".join(next_items) +
           "\n\n" + invariants + "\n\nSpec == Init /\\ [][Next]_vars\n====\n")
    cfg = ("SPECIFICATION\nSpec\n\nINVARIANT\nTypeOK\n" +
           "".join(f"\nINVARIANT\n{item.id}\n" for item in spec.tlc_invariants))
    return tla, cfg
