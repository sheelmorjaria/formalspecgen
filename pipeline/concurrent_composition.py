"""Deterministic concurrent-composition model preparation."""
from __future__ import annotations

import re


def render_actor_model(actors: list[str], operation: str = "call") -> dict:
    """Render a bounded actor/call-result TLA+ skeleton without a proof claim."""
    if not actors or len(actors) != len(set(actors)) or any(
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", actor) for actor in actors):
        return {"status": "CONCURRENT_MODEL_INVALID", "claim": "NO_PROOF"}
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", operation):
        return {"status": "CONCURRENT_MODEL_INVALID", "claim": "NO_PROOF"}
    actor_set = "{" + ", ".join(actors) + "}"
    tla = f"""---- MODULE ConcurrentComposition ----
EXTENDS Naturals, Sequences
Actors == {actor_set}
VARIABLES actorState, callResult, history
Init == /\\ actorState = [a \\in Actors |-> \"idle\"]
       /\\ callResult = [a \\in Actors |-> \"unavailable\"]
       /\\ history = <<>>
Invoke(a) == /\\ a \\in Actors
              /\\ actorState' = [actorState EXCEPT ![a] = \"{operation}\"]
              /\\ UNCHANGED <<callResult, history>>
Complete(a, result) == /\\ a \\in Actors
                       /\\ callResult' = [callResult EXCEPT ![a] = result]
                       /\\ actorState' = [actorState EXCEPT ![a] = \"idle\"]
                       /\\ history' = Append(history, [actor |-> a, result |-> result])
Next == \\E a \\in Actors : Invoke(a) \\/ \\E a \\in Actors, r : Complete(a, r)
====
"""
    return {"status": "CONCURRENT_MODEL_READY", "claim": "NO_PROOF",
            "concurrent_linearizability_proved": False, "actors": actors,
            "call_result_variable": "callResult", "tla": tla}
