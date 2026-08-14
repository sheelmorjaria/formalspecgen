# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic TLA+ rendering for staged architecture transition fragments."""
from __future__ import annotations

from .domain_v2_tla import render_expression
from .staged_architecture import StateVariableFragment, TransitionFragment, validate_transition
from .staged_architecture import UnifiedArchitecture


def render_transition(name: str, transition: TransitionFragment,
                      variables: list[str]) -> str:
    validate_transition(transition, set(variables))
    lines = [f"{name} ==", f"    /\\ {render_expression(transition.precondition)}"]
    lines.extend(f"    /\\ {effect.target}' = {render_expression(effect.value)}"
                 for effect in transition.effects)
    unchanged = [item for item in variables if item not in transition.frame]
    if unchanged:
        lines.append(f"    /\\ UNCHANGED <<{', '.join(unchanged)}>>")
    return "\n".join(lines)


def render_architecture_tla(states: list[StateVariableFragment],
                            transitions: list[tuple[str, TransitionFragment]],
                            module_name: str = "Architecture") -> tuple[str, str]:
    """Render a finite state model and CFG; callers must run TLC before publication."""
    if not states:
        raise ValueError("UNBOUNDED_STATE_SPACE: no bounded state variables declared")
    if any(state.type not in {"int", "boolean", "bool"} or
           (state.type == "int" and state.bound is None) for state in states):
        raise ValueError("UNBOUNDED_STATE_SPACE: every integer state requires a bound")
    variables = [state.name for state in states]
    lines = [f"---- MODULE {module_name} ----", "EXTENDS Naturals", "",
             "VARIABLES " + ", ".join(variables), "", "Init =="]
    lines.extend(f"    /\\ {state.name} = "
                 f"{'TRUE' if state.initial else 'FALSE'}" if state.type != "int"
                 else f"    /\\ {state.name} = {state.initial}" for state in states)
    lines.extend(["", "TypeOK =="])
    for state in states:
        domain = "BOOLEAN" if state.type != "int" else f"{state.bound[0]}..{state.bound[1]}"
        lines.append(f"    /\\ {state.name} \\in {domain}")
    lines.append("")
    for name, transition in transitions:
        lines.extend([render_transition(name, transition, variables), ""])
    action_names = [name for name, _ in transitions]
    lines.append("Next == " + (" \\/ ".join(action_names) if action_names else "UNCHANGED <<" + ", ".join(variables) + ">>"))
    lines.extend(["Spec == Init /\\ [][Next]_<<" + ", ".join(variables) + ">>", "", "===="])
    # TLC checks deadlocks by default; omitting CHECK_DEADLOCK avoids the
    # non-boolean config syntax accepted by some TLC versions only.
    cfg = "SPECIFICATION Spec\nINVARIANT TypeOK\n"
    return "\n".join(lines) + "\n", cfg


def render_unified_architecture(architecture: UnifiedArchitecture) -> tuple[str, str]:
    """Lower the unified component schema into one bounded architecture model."""
    states = [state for component in architecture.components
              for state in component.state_variables]
    transitions = [(transition.operation_name, transition)
                   for component in architecture.components
                   for transition in component.transitions]
    return render_architecture_tla(states, transitions, architecture.name)
