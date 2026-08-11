import json
from pathlib import Path

import pytest

from pipeline import orchestrator
from pipeline.implementation import synthesize_implementation


pytestmark = pytest.mark.live_llm


def test_live_ollama_requirement_to_verified_implementation(
        require_live_llm, openjml_tool, tmp_path):
    requirement = (
        "A Java counter starts at zero. Its integer value is always between 0 and 1000. "
        "A void add operation accepts a positive integer amount only when the resulting value "
        "does not exceed 1000, and increases the value by exactly that amount.")
    draft_dir = tmp_path / "draft"
    draft = orchestrator.run(
        requirement, provider="ollama", out_dir=draft_dir,
        max_attempts=3, resample_budget=1, feedback_budget=2)
    assert draft.final_status == "VERIFIED"
    stub = Path(draft.stub_path).read_text(encoding="utf-8")
    implementation_dir = tmp_path / "implementation"
    result = synthesize_implementation(
        stub, provider="ollama", out_dir=implementation_dir,
        max_attempts=4, resample_budget=2, feedback_budget=2)
    verdict = json.loads((implementation_dir / "verdict.json").read_text(encoding="utf-8"))
    assert result["final_status"] == verdict["final_status"] == "VERIFIED"
    assert verdict["claim"] == "DEDUCTIVE_PROOF"
    assert verdict["external_handoff_used"] is False
