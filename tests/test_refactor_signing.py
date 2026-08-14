from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pipeline import cli


def test_verify_refactor_can_sign_json_verdict(tmp_path):
    verdict = tmp_path / "verdict.json"
    args = SimpleNamespace(baseline="baseline.java", refactored="refactored.java",
                           json=str(verdict), signing_key="reviewer")
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    proof = {"status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED"}
    with patch("pipeline.refactor_gate.verify_contract_preserving_refactor", return_value=proof), \
            patch("pipeline.domain_v2_promotion.sign_artifact",
                  return_value=Path(str(verdict) + ".sig")) as sign:
        assert cli.command_verify_refactor(args, ui) == 0
    sign.assert_called_once_with(str(verdict), "reviewer")


def test_verify_refactor_rejects_signing_without_json():
    args = SimpleNamespace(baseline="baseline.java", refactored="refactored.java",
                           json=None, signing_key="reviewer")
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    assert cli.command_verify_refactor(args, ui) == 2
