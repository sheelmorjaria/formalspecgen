# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic reviewed-V2 refinement certificates for Rust and C."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .v2_acsl_serializer import render_translation_unit
from .v2_prusti_serializer import render_struct
from .v2_refinement import RefinementBoundaryError, load_bound_reviewed_domain


def polyglot_v2_refinement_gate(
        reviewed_path: str | Path, validation_path: str | Path,
        contract_code: str, implementation_code: str, language: str, *,
        backend_verified: bool, tlc_verified: bool = True) -> dict:
    """Bind an unchanged native contract surface and its proof to reviewed V2."""
    def fail(code: str, message: str, obligations=None) -> dict:
        return {"status": "FAIL", "code": code, "message": message,
                "source_refinement_proved": False, "obligations": obligations or []}

    if language not in {"rust", "c"}:
        return fail("unsupported_language", "Polyglot refinement supports Rust and C")
    if not backend_verified:
        return fail("backend_not_verified", "Implementation has no native deductive proof")
    if not tlc_verified:
        return fail("tlc_not_verified", "V2 model has no successful TLC result")
    try:
        reviewed = load_bound_reviewed_domain(reviewed_path, validation_path)
        expected = render_struct(reviewed) if language == "rust" else render_translation_unit(reviewed)
        # Imported lazily to avoid coupling serializer imports to the synthesis loop.
        from .polyglot_implementation import trusted_surface_matches
        canonical, canonical_diff = trusted_surface_matches(expected, contract_code, language)
        preserved, implementation_diff = trusted_surface_matches(
            contract_code, implementation_code, language)
    except RefinementBoundaryError as exc:
        return fail(exc.code, str(exc))
    except (OSError, ValueError, KeyError) as exc:
        return fail("unsupported_refinement_boundary", str(exc))
    if not canonical:
        return fail("canonical_contract_mismatch",
                    "Trusted native contract is not the deterministic reviewed-V2 rendering",
                    [{"surface": key, "status": "FAILED"}
                     for key in canonical_diff])
    if not preserved:
        return fail("trusted_contract_changed",
                    "Implementation changed the trusted native contract surface",
                    [{"surface": key, "status": "FAILED"}
                     for key in implementation_diff])

    obligations = [{"operation": operation.name,
                    "native_symbol": _native_symbol(reviewed.module_name, operation.name, language),
                    "contract_aligned": True, "proof_discharged": True, "status": "PROVED"}
                   for operation in reviewed.operations]
    body = {
        "domain": reviewed.module_name,
        "language": language,
        "scope": "v2_atomic_contract_refinement",
        "accepted_candidate_sha256": reviewed.accepted_candidate_sha256,
        "evidence_sha256": reviewed.accepted_evidence_sha256,
        "trusted_contract_sha256": hashlib.sha256(contract_code.encode()).hexdigest(),
        "implementation_sha256": hashlib.sha256(implementation_code.encode()).hexdigest(),
        "obligations": obligations,
    }
    certificate = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"status": "VERIFIED", "claim": "SOURCE_MODEL_REFINEMENT",
            "scope": body["scope"], "language": language,
            "source_refinement_proved": True,
            "concurrent_linearizability_proved": False,
            "obligations": obligations,
            "trusted_contract_sha256": body["trusted_contract_sha256"],
            "implementation_sha256": body["implementation_sha256"],
            "certificate_sha256": certificate}


def _native_symbol(module: str, operation: str, language: str) -> str:
    snake = "".join(("_" + char.lower()) if char.isupper() else char
                    for char in operation).lstrip("_")
    return snake if language == "rust" else f"{module}_{snake}"
