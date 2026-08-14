import json

import pytest

from pipeline.unified_system_runner import _load_reviewed_domain


def test_unified_domain_loading_enforces_opt_in_signature_policy(tmp_path, monkeypatch):
    domains = tmp_path / "domains"; domains.mkdir()
    path = domains / "gate.json"
    path.write_text(json.dumps({"review_status": "reviewed"}))
    monkeypatch.setenv("FORMALSPECGEN_REQUIRE_SIGNATURES", "1")
    with pytest.raises(ValueError, match="Cryptographic signature verification failed"):
        _load_reviewed_domain("gate", domains)
