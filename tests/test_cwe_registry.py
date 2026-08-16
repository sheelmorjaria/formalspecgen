"""Tests for the configuration-driven CWE manifest registry."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from pipeline import cwe_registry
from pipeline.cwe_registry import (
    ManifestError,
    by_rule_id,
    by_vc_label,
    correction_guidance,
    load_manifest,
    mitigated_formal_cwes,
    native_trigger_findings,
    remediation_prompt,
)

NEW_CWE = {
    "cwe_id": "CWE-9999",
    "name": "Test Weakness",
    "severity": "MEDIUM",
    "languages": ["java"],
    "detection": {"method": "sast", "vc_labels": [], "native_triggers": {},
                  "semgrep_rule_ids": ["TEST-NEW-RULE"]},
    "poc_supported": [],
    "remediation_prompt": " Do the test remediation.",
    "correction_guidance": "Test correction guidance."}


def test_shipped_manifest_loads_and_every_reference_resolves():
    entries = cwe_registry.entries()
    assert len(entries) >= 19
    for entry in entries.values():
        assert entry.method in {"formal", "sast", "manual"}
    # every vc label and rule id resolves to an entry (no dangling references)
    assert by_vc_label("PossiblyNegativeIndex").cwe_id == "CWE-125"
    assert by_rule_id("CWE-798-HARDCODED-CREDENTIALS").cwe_id == "CWE-798"
    assert by_rule_id("CWE-415-DOUBLE-FREE").cwe_id == "CWE-415"
    # every java_custom.yml / c_custom.yml rule id is declared in the manifest
    declared = {rule for entry in entries.values() for rule in entry.semgrep_rule_ids}
    for config in ("security/java_custom.yml", "security/c_custom.yml"):
        for rule in yaml.safe_load(Path(config).read_text(encoding="utf-8"))["rules"]:
            assert rule["id"] in declared, f"{rule['id']} missing from cwe_manifest.json"
    # CWE-89 has no dedicated rule (detected via SQL-pattern findings) — allowed
    assert by_rule_id("UNKNOWN-RULE") is None


def test_manifest_extension_requires_no_code_changes(tmp_path):
    """Adding a CWE block to a manifest instantly wires every lookup."""
    manifest = tmp_path / "cwe_manifest.json"
    manifest.write_text(json.dumps([NEW_CWE]), encoding="utf-8")
    loaded = load_manifest(manifest)
    assert loaded["CWE-9999"].remediation_prompt == " Do the test remediation."
    # a copy of the shipped manifest plus the new entry resolves the new rule id
    shipped = json.loads(Path("security/cwe_manifest.json").read_text(encoding="utf-8"))
    extended = tmp_path / "extended.json"
    extended.write_text(json.dumps(shipped + [NEW_CWE]), encoding="utf-8")
    monkey_entries = load_manifest(extended)
    cwe_registry.entries.cache_clear()
    original = cwe_registry._MANIFEST
    try:
        cwe_registry._MANIFEST = extended
        assert by_rule_id("TEST-NEW-RULE").cwe_id == "CWE-9999"
        assert correction_guidance("CWE-9999") == "Test correction guidance."
        assert remediation_prompt(["CWE-9999"]) == " Do the test remediation."
    finally:
        cwe_registry._MANIFEST = original
        cwe_registry.entries.cache_clear()
    assert monkey_entries["CWE-9999"].severity == "MEDIUM"


@pytest.mark.parametrize("mutation, match", [
    ({"cwe_id": "BAD"}, "invalid cwe_id"),
    ({"detection": {"method": "psychic"}}, "invalid detection method"),
    ({"languages": ["klingon"]}, "unknown languages"),
    ({}, "duplicate"),
])
def test_malformed_manifests_fail_closed(tmp_path, mutation, match):
    base = json.loads(json.dumps(NEW_CWE))
    base.update({key: value for key, value in mutation.items() if key != "detection"})
    if "detection" in mutation:
        base["detection"] = mutation["detection"]
    manifest = tmp_path / "bad.json"
    manifest.write_text(json.dumps([NEW_CWE, base] if match == "duplicate"
                                   else [base]), encoding="utf-8")
    with pytest.raises(ManifestError, match=match):
        load_manifest(manifest)
    (tmp_path / "empty.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ManifestError, match="non-empty"):
        load_manifest(tmp_path / "empty.json")


def test_native_trigger_matching_prefers_longest_and_handles_and(tmp_path):
    assert native_trigger_findings("openjml", "arithmeticoperationrange underflow")[
        "cwe"] == "CWE-191"
    assert native_trigger_findings("openjml", "arithmeticoperationrange")["cwe"] == "CWE-190"
    # "null and derefer" requires both words, matching the original two-substring rule
    assert native_trigger_findings("openjml", "may be null when dereferenced")[
        "cwe"] == "CWE-476"
    assert native_trigger_findings("prusti", "precondition of method: index")[
        "cwe"] == "CWE-125"
    assert native_trigger_findings("framac", "RTE: signed_overflow")["cwe"] == "CWE-190"
    assert native_trigger_findings("other", "anything") == {"cwe": "UNKNOWN",
                                                            "severity": "LOW"}


def test_remediation_and_correction_guidance_fall_back_cleanly():
    assert "least-privilege" in remediation_prompt(["CWE-732"])
    assert "environment variables" in remediation_prompt(["CWE-798"])
    assert remediation_prompt(["CWE-NOPE"]) == ""
    assert "conditional postconditions" in correction_guidance("CWE-125")
    assert "null handling" in correction_guidance("CWE-476")
    assert correction_guidance("CWE-NOPE") == cwe_registry.DEFAULT_CORRECTION_GUIDANCE
    assert "CWE-125" in mitigated_formal_cwes()
    assert "CWE-22" not in mitigated_formal_cwes()


def test_malformed_entries_and_unknown_variants_fail_closed(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps([{"cwe_id": "CWE-1", "severity": "HIGH"}]),
                      encoding="utf-8")  # missing name + detection
    with pytest.raises(ManifestError, match="malformed CWE entry"):
        load_manifest(broken)
    from pipeline.cwe_registry import variant_entry
    assert variant_entry("CWE-NOPE", "underflow") is None
    assert variant_entry("CWE-835", "underflow") is None  # exists but declares no variants
