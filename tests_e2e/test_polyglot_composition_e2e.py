"""E2E: polyglot composition proof with the REAL Prusti prover."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.toolchain


def test_rust_composition_proves_with_real_prusti(tmp_path):
    try:
        from pipeline.config import PRUSTI_BIN
        if not Path(PRUSTI_BIN).exists():
            pytest.skip(f"Prusti unavailable: {PRUSTI_BIN}")
    except Exception:
        pytest.skip("Prusti unavailable")

    from pipeline.polyglot_composition import verify_polyglot_composition
    artifact = {
        "system_name": "Checkout",
        "architecture": {"components": [
            {"id": "payments", "name": "PaymentGateway", "type": "interface",
             "external": True, "adapter": "StripePaymentGateway",
             "operations": [{"name": "charge",
                             "parameters": [{"name": "amount", "type": "int"}],
                             "returns": "boolean",
                             "requires": ["amount > 0"],
                             "ensures": ["\\result ==> amount > 0"],
                             "assignable": []}]},
        ]},
        "bindings": [{"component": "payments", "module_name": "smart_lock"}],
        "use_cases": [{"name": "charge order",
                       "steps": [{"component": "payments", "operation": "charge",
                                  "arguments": {"amount": "amount"}}]}],
    }
    result = verify_polyglot_composition(
        artifact, v2_dir=str(Path("domains/v2")), language="rust")
    assert result["status"] == "COMPOSITION_VERIFIED", json.dumps(result, default=str)[:800]
    assert result["claim"] == "SYSTEM_COMPOSITION_PROOF"
    assert result["unverified_boundaries"] == ["StripePaymentGateway"]
    assert result["external_io_safety_proved"] is False
