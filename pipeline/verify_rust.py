# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Rust verifier adapter exposing compiler, Prusti, and Kani through one result schema."""
from __future__ import annotations

from .kani import verify_kani
from .rust_support import check_rust_syntax, lint_rust, verify_prusti


def verify_rust(code: str, mode: str = "esc", backend: str = "prusti") -> dict:
    findings = lint_rust(code)
    if any(item.get("severity") == "error" for item in findings):
        return {"status": "RUST_LINT_FAILED", "exit_code": 2, "claim": "NO_PROOF",
                "language": "rust", "warnings": findings, "vcs": []}
    if backend == "kani":
        result = verify_kani(code)
    elif mode == "esc":
        result = verify_prusti(code)
    else:
        result = check_rust_syntax(code)
    status = result.get("status")
    claim = ("DEDUCTIVE_PROOF" if backend == "prusti" and mode == "esc" and status == "VERIFIED"
             else "BOUNDED_EVIDENCE" if backend == "kani" and status == "VERIFIED"
             else "STATIC_CHECK" if status == "RUST_CHECKED" else "NO_PROOF")
    return {**result, "language": "rust", "warnings": findings, "claim": claim}
