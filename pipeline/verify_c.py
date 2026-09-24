# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""C/ACSL verifier adapter exposing strict compilation and Frama-C WP consistently."""
from __future__ import annotations

from .c_support import check_c_syntax, verify_framac
from .verification_policy import decide_result


def verify_c(code: str, mode: str = "esc") -> dict:
    result = verify_framac(code) if mode == "esc" else check_c_syntax(code)
    return {**decide_result(result, tool="frama-c" if mode == "esc" else "cc", mode=mode),
            "language": "c"}
