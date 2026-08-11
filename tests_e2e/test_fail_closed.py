import json

import pytest

from pipeline.implementation import synthesize_implementation
from pipeline.jml_to_dafny import UnsupportedBoundary, translate_jml_to_dafny

from fixtures import COUNTER, TRUSTED_COUNTER_STUB


pytestmark = pytest.mark.toolchain


def test_contract_change_is_terminal_and_writes_no_proof(tmp_path):
    changed = COUNTER.replace("amount <= 1000 - value", "amount <= 999 - value")
    result = synthesize_implementation(
        TRUSTED_COUNTER_STUB, candidate=changed, out_dir=tmp_path, max_attempts=1)
    verdict = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert result["final_status"] == "TRUST_BOUNDARY_VIOLATION"
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["attempts"][0]["status"] == "TRUST_BOUNDARY_VIOLATION"


def test_unknown_dafny_shape_never_emits_hybrid_source():
    with pytest.raises(UnsupportedBoundary, match="no known"):
        translate_jml_to_dafny("public class C { public static int f(int x) { return x; } }")
