"""Configuration-driven CWE registry loaded from security/cwe_manifest.json.

One JSON block per CWE drives formal label mapping, native-verifier diagnostic
mapping, semgrep rule-id translation, remediation prompts, and correction
guidance, so a new weakness drops in without touching orchestrator logic.
A malformed manifest fails loudly; it never silently yields an empty registry.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import config

_MANIFEST = config.resource_path("security", "cwe_manifest.json")
_CWE_ID = re.compile(r"^CWE-\d+$")
_METHODS = {"formal", "sast", "manual"}
_LANGUAGES = {"java", "rust", "c", "cpp"}

DEFAULT_CORRECTION_GUIDANCE = (
    "Define explicit safe behavior for the reported weakness and preserve the public "
    "method signatures.")


class ManifestError(ValueError):
    """The CWE manifest is structurally invalid; the security lane must fail closed."""


@dataclass(frozen=True)
class CweEntry:
    cwe_id: str
    name: str
    severity: str
    languages: tuple[str, ...]
    method: str
    vc_labels: tuple[str, ...] = ()
    native_triggers: dict[str, tuple[str, ...]] = field(default_factory=dict)
    semgrep_rule_ids: tuple[str, ...] = ()
    variants: dict[str, str] = field(default_factory=dict)
    fuzzy_diagnostics: tuple[str, ...] = ()
    synthesis_trigger: str | None = None
    poc_supported: tuple[str, ...] = ()
    remediation_prompt: str = ""
    correction_guidance: str = ""

    def formal_finding(self, vc_label: str) -> dict[str, str]:
        return {"source": "openjml_esc", "vc": vc_label, "cwe": self.cwe_id,
                "severity": self.severity, "description": self.name}


def _parse_entry(raw: dict[str, Any]) -> CweEntry:
    try:
        detection = raw["detection"]
        entry = CweEntry(
            cwe_id=raw["cwe_id"], name=raw["name"], severity=raw["severity"],
            languages=tuple(raw.get("languages", ("java",))),
            method=detection["method"],
            vc_labels=tuple(detection.get("vc_labels", [])),
            native_triggers={verifier: tuple(triggers) for verifier, triggers
                             in detection.get("native_triggers", {}).items()},
            semgrep_rule_ids=tuple(detection.get("semgrep_rule_ids", [])),
            variants=dict(raw.get("variants", {})),
            fuzzy_diagnostics=tuple(raw.get("fuzzy_diagnostics", [])),
            synthesis_trigger=(raw.get("diagnostic_synthesis", {})
                               .get("when_output_contains")),
            poc_supported=tuple(raw.get("poc_supported", [])),
            remediation_prompt=raw.get("remediation_prompt", ""),
            correction_guidance=raw.get("correction_guidance", ""))
    except (KeyError, TypeError) as exc:
        raise ManifestError(f"malformed CWE entry ({exc}): {raw!r:.200}") from exc
    if not _CWE_ID.match(entry.cwe_id):
        raise ManifestError(f"invalid cwe_id: {entry.cwe_id!r}")
    if entry.method not in _METHODS:
        raise ManifestError(f"invalid detection method for {entry.cwe_id}: {entry.method!r}")
    unknown = set(entry.languages) - _LANGUAGES
    if unknown:
        raise ManifestError(f"unknown languages for {entry.cwe_id}: {sorted(unknown)}")
    return entry


def load_manifest(path: str | Path = _MANIFEST) -> dict[str, CweEntry]:
    """Parse and validate a manifest file; raises ManifestError on any defect."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ManifestError("manifest must be a non-empty JSON list")
    entries = {raw["cwe_id"]: _parse_entry(raw) for raw in data if isinstance(raw, dict)}
    duplicates = len(data) - len(entries)
    non_objects = sum(1 for raw in data if not isinstance(raw, dict))
    if duplicates or non_objects:
        raise ManifestError("manifest contains duplicate cwe_id values or non-object rows")
    return entries


@lru_cache(maxsize=1)
def entries() -> dict[str, CweEntry]:
    return load_manifest(_MANIFEST)


def by_vc_label(label: str) -> CweEntry | None:
    return next((entry for entry in entries().values()
                 if label in entry.vc_labels), None)


def by_rule_id(rule_id: str) -> CweEntry | None:
    return next((entry for entry in entries().values()
                 if rule_id in entry.semgrep_rule_ids), None)


def native_trigger_findings(verifier: str, failure_text: str) -> dict[str, str]:
    """Map native prover diagnostics through manifest triggers (longest match first)."""
    text = failure_text.lower()
    ranked: list[tuple[int, str, str]] = []
    for entry in entries().values():
        for trigger in entry.native_triggers.get(verifier, ()):
            if all(part in text for part in trigger.split(" and ")):
                ranked.append((len(trigger), entry.cwe_id, entry.severity))
    if not ranked:
        return {"cwe": "UNKNOWN", "severity": "LOW"}
    _, cwe, severity = max(ranked)
    return {"cwe": cwe, "severity": severity}


def variant_entry(cwe_id: str, variant: str) -> CweEntry | None:
    base = entries().get(cwe_id)
    if base is None:
        return None
    variant_id = base.variants.get(variant)
    return entries().get(variant_id) if variant_id else None


def remediation_prompt(cwes: list[str]) -> str:
    """Concatenate manifest remediation guidance for the reported CWEs."""
    guidance = ""
    for cwe in cwes:
        entry = entries().get(cwe)
        prompt = entry.remediation_prompt if entry else ""
        if prompt:
            guidance += " " + prompt.strip()
    return guidance


def correction_guidance(cwe: str) -> str:
    entry = entries().get(cwe)
    return entry.correction_guidance if entry and entry.correction_guidance \
        else DEFAULT_CORRECTION_GUIDANCE


def mitigated_formal_cwes() -> list[str]:
    """CWEs whose formal obligations the OpenJML lane is able to discharge."""
    return sorted(entry.cwe_id for entry in entries().values()
                  if entry.method == "formal" and entry.vc_labels)
