# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M58: Z3-judged bounded post-quantum TLS session-pool capacity."""
from __future__ import annotations

import hashlib
import shutil
import subprocess


def _fail(code: str, message: str = "") -> dict:
    return {"status": "PQ_TLS_POOL_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_pq_tls_pool(artifact: dict, profile: dict) -> dict:
    """Prove the declared capacity is the exact positive budget ceiling."""
    target = profile.get("target")
    budgets = artifact.get("profile_budgets")
    components = artifact.get("session_components_bytes")
    capacity = artifact.get("capacity")
    alignment = artifact.get("alignment_bytes")
    if not isinstance(target, str) or not isinstance(budgets, dict) \
            or not isinstance(budgets.get(target), int):
        return _fail("PQ_TLS_PROFILE_MISSING",
                     "artifact must bind a budget to the named hardware profile")
    if not isinstance(components, dict) or not components:
        return _fail("PQ_TLS_COMPONENTS_MISSING")
    if not all(isinstance(value, int) and not isinstance(value, bool) and value > 0
               for value in components.values()):
        return _fail("PQ_TLS_COMPONENT_SIZE_INVALID")
    if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity <= 0:
        return _fail("PQ_TLS_CAPACITY_INVALID")
    if not isinstance(alignment, int) or alignment <= 0:
        return _fail("PQ_TLS_ALIGNMENT_INVALID")
    raw_size = sum(components.values())
    session_size = ((raw_size + alignment - 1) // alignment) * alignment
    budget = budgets[target]
    if budget <= 0:
        return _fail("PQ_TLS_BUDGET_INVALID")
    z3 = shutil.which("z3")
    if z3 is None:
        return _fail("z3_unavailable")
    encoding = (
        "(set-logic QF_LIA)\n"
        f"(define-fun capacity () Int {capacity})\n"
        f"(define-fun session_size () Int {session_size})\n"
        f"(define-fun budget () Int {budget})\n"
        "(assert (or (> (* capacity session_size) budget)\n"
        "            (<= (* (+ capacity 1) session_size) budget)))\n"
        "(check-sat)\n")
    try:
        result = subprocess.run([z3, "-in"], input=encoding, text=True,
                                capture_output=True, timeout=30)
        version = subprocess.run([z3, "--version"], text=True,
                                 capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _fail("z3_failed", str(exc))
    if result.returncode != 0 or result.stdout.strip() != "unsat":
        return _fail("PQ_TLS_CAPACITY_NOT_EXACT", result.stdout.strip())
    return {
        "status": "PQ_TLS_POOL_BOUND_PROVED",
        "claim": "HARDWARE_MEMORY_BOUND_PROVED",
        "scope": "pq_tls_session_pool", "judge": "z3",
        "solver_version": version.stdout.strip(),
        "encoding_sha256": hashlib.sha256(encoding.encode()).hexdigest(),
        "capacity": capacity, "session_size_bytes": session_size,
        "footprint_bytes": capacity * session_size, "budget_bytes": budget,
        "backpressure": "ERR_MEM", "cryptographic_strength_proved": False,
        "liboqs_implementation_proved": False,
    }
