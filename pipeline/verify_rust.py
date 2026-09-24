# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Rust verifier adapter exposing compiler, Prusti, and Kani through one result schema."""
from __future__ import annotations

from .kani import verify_kani
from .rust_support import check_rust_syntax, lint_rust, verify_prusti
from .verification_policy import decide_result


def verify_rust(code: str, mode: str = "esc", backend: str = "prusti") -> dict:
    findings = lint_rust(code)
    if any(item.get("severity") == "error" for item in findings):
        result = {"status": "RUST_LINT_FAILED", "exit_code": 2,
                  "claim": "NO_PROOF", "vcs": []}
        return {**decide_result(result, tool=backend, mode=mode),
                "language": "rust", "warnings": findings}
    if backend == "kani":
        result = verify_kani(code)
    elif mode == "esc":
        result = verify_prusti(code)
    else:
        result = check_rust_syntax(code)
    decided = decide_result(result, tool=backend if mode == "esc" else "rustc", mode=mode)
    return {**decided, "language": "rust", "warnings": findings}
