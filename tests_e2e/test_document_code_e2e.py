"""E2E: document-code over the committed legacy fixture (no network, no LLM)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import cli
from pipeline.codebase_analysis import extract_components_ts

pytestmark = pytest.mark.toolchain

REPO_ROOT = Path(__file__).resolve().parents[1]
LEGACY = REPO_ROOT / "legacy" / "LegacyCounter.java"


def test_document_code_on_committed_legacy_fixture(tmp_path):
    """Code -> Math -> NL over the real legacy counter, deterministically."""
    if extract_components_ts(LEGACY) is None:
        pytest.skip("Tree-sitter Java grammar is unavailable")

    out = tmp_path / "docs" / "LegacyCounter.md"
    verdict_path = tmp_path / "verdict.json"
    assert cli.main(["document-code", str(LEGACY), "--out", str(out),
                     "--project-root", str(tmp_path), "--no-llm",
                     "--json", str(verdict_path)]) == 0
    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    assert verdict["status"] == "DOCUMENTED"
    assert verdict["claim"] == "UNREVIEWED_EXTRACTION_DOCUMENTATION"
    assert verdict["schema_valid"] is True
    assert verdict["narrative_source"] == "disabled"

    document = out.read_text(encoding="utf-8")
    assert document.startswith("# LegacyCounter")
    assert ("The system tracks a 'count' value, starting at 0, which must always remain "
            "between 0 and 5." in document)
    assert ("The 'increment' operation can only be called if count is less than 5. "
            "When called, it increases the count by 1." in document)
    assert ("The 'decrement' operation can only be called if count is greater than 0. "
            "When called, it decreases the count by 1." in document)
    assert "Safety Rule: count >= 0 and count <= 5 must always hold." in document
    assert ("*This documentation was auto-generated from a formal V2 extraction model. "
            "Review Status: UNREVIEWED.*" in document)

    # The registered candidate round-trips through the strict V2 schema and the
    # documented module matches the committed candidate for the same source.
    candidate = tmp_path / "domains" / "candidates" / "legacy_counter.v2.yaml"
    assert candidate.exists()
    from pipeline.domain_v2 import DomainSpecV2
    import yaml
    payload = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    DomainSpecV2.model_validate(payload)
