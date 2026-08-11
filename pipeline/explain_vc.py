# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Stable, offline explanations for common OpenJML verification conditions."""


_EXPLANATIONS = {
    "ArithmeticOperationRange": (
        "The verifier cannot prove that this arithmetic operation stays within the Java numeric range.",
        "Add sound input bounds or a loop invariant bounding the intermediate value; consider inject_overflow_bounds."
    ),
    "ArrayAccess": (
        "The verifier cannot prove that the array index is between zero and the array length.",
        "Add an index-bound precondition or loop invariant, and establish that the array is non-null."
    ),
    "PossiblyNullDeReference": (
        "The verifier cannot prove that this reference is non-null at the dereference.",
        "Add a non-null precondition or prove the reference was initialized on every path."
    ),
    "Postcondition": (
        "At least one method exit is not strong enough to establish the declared postcondition.",
        "Trace the failing exit backward and strengthen the implementation invariant; do not weaken the contract without human review."
    ),
    "Precondition": (
        "A call site does not establish all preconditions required by the called method.",
        "Prove the required facts before the call or correct the caller/callee contract mismatch."
    ),
    "LoopInvariant": (
        "The loop invariant is not established initially or is not preserved by one iteration.",
        "Check the invariant at loop entry, then symbolically execute one iteration and add the missing relational bound."
    ),
    "LoopDecreases": (
        "The termination measure is not proved non-negative and strictly decreasing.",
        "Choose a measure tied to the loop guard and show how every iteration reduces it."
    ),
    "Assignable": (
        "The implementation may modify memory outside the method's frame condition.",
        "Narrow the writes or update the assignable clause after human review."
    ),
}


def explain_vc(category: str, detail: str = "") -> dict:
    explanation, advice = _EXPLANATIONS.get(category, (
        "OpenJML could not establish this verification condition from the current contracts and invariants.",
        "Inspect the associated declaration and failing line, then add the smallest sound fact needed by the proof."
    ))
    if detail and "overflow" in detail.lower() and category != "ArithmeticOperationRange":
        explanation, advice = _EXPLANATIONS["ArithmeticOperationRange"]
    return {"explanation": explanation, "advice": advice}
