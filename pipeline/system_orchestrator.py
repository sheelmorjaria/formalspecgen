# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed subprocess decomposition for reviewed component systems."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .composition import CompositionSpec
from .java_inspection import inspect_java_file
from .deterministic_refactor import extract_factory_from_inspection, extract_method_from_inspection
from .refactor_gate import verify_contract_preserving_refactor, verify_multifile_contract_refactor


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SystemComponent(_StrictModel):
    component: str
    interface_file: str
    reviewed_domain: str
    validation_evidence: str
    assurance_level: Literal["critical", "standard", "lightweight"] = "critical"

    @field_validator("component")
    @classmethod
    def safe_component(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("component must be a safe identifier")
        return value


class SystemSpec(_StrictModel):
    schema_version: Literal[1] = 1
    system_name: str
    composition: CompositionSpec
    components: list[SystemComponent] = Field(min_length=1)

    @model_validator(mode="after")
    def complete_components(self) -> "SystemSpec":
        names = [item.component for item in self.components]
        if len(names) != len(set(names)):
            raise ValueError("system component implementations must be unique")
        bound = {item.component for item in self.composition.bindings}
        if set(names) != bound:
            raise ValueError("system implementations must cover composition bindings exactly")
        if self.system_name != self.composition.system_name:
            raise ValueError("system name must match embedded composition")
        return self


def parse_system(value: dict | str) -> SystemSpec:
    return SystemSpec.model_validate(json.loads(value) if isinstance(value, str) else value)


def _component_command(component: SystemComponent, verdict: Path,
                       executable: str) -> list[str]:
    return [executable, "implement", component.interface_file,
            "--assurance-level", component.assurance_level,
            "--v2-reviewed-domain", component.reviewed_domain,
            "--v2-validation-evidence", component.validation_evidence,
            "--json", str(verdict)]


def verify_system(value: dict | str, *, out_dir: str | Path,
                  max_workers: int = 4, executable: str = "formalspecgen",
                  popen=subprocess.Popen, composition_gate=None) -> dict:
    """Verify isolated components concurrently, then invoke composition exactly once."""
    try:
        spec = parse_system(value)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return _fail("invalid_system_artifact", str(exc))
    if max_workers < 1:
        return _fail("invalid_worker_count", "max_workers must be positive")
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)

    def run(component: SystemComponent) -> dict:
        component_dir = root / component.component
        component_dir.mkdir(parents=True, exist_ok=True)
        verdict_path = component_dir / "verdict.json"
        command = _component_command(component, verdict_path, executable)
        try:
            process = popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            exit_code = process.returncode
        except OSError as exc:
            stdout, stderr, exit_code = "", str(exc), 127
        try:
            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            verdict = {"final_status": "MISSING_VERDICT", "claim": "NO_PROOF"}
        return {"component": component.component, "exit_code": exit_code,
                "command": command, "stdout": stdout, "stderr": stderr,
                "verdict_path": str(verdict_path), "verdict": verdict}

    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(spec.components))) as pool:
        futures = {pool.submit(run, item): item.component for item in spec.components}
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: item["component"])
    failed = [item for item in results if item["exit_code"] != 0 or
              item["verdict"].get("claim") in {None, "NO_PROOF"}]
    if failed:
        return {**_fail("component_verification_failed",
                        "At least one isolated component failed verification"),
                "status": "SYSTEM_SYNTHESIS_FAILED", "components": results}
    if composition_gate is None:
        from .composition_render import verify_composition
        composition_gate = verify_composition
    composition = composition_gate(spec.composition.model_dump(mode="json"))
    if composition.get("status") != "COMPOSITION_VERIFIED":
        return {**_fail("composition_verification_failed",
                        "Verified components did not produce a composition proof"),
                "status": "SYSTEM_SYNTHESIS_FAILED", "components": results,
                "composition": composition}
    body = {"system": spec.system_name,
            "component_verdict_sha256": {
                item["component"]: hashlib.sha256(json.dumps(
                    item["verdict"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                for item in results},
            "composition_claim": composition.get("claim")}
    return {"status": "SYSTEM_SYNTHESIS_VERIFIED", "claim": "SYSTEM_COMPOSITION_PROOF",
            "scope": "isolated_component_proofs_plus_scoped_composition",
            "components": results, "composition": composition,
            "certificate_sha256": hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "concurrent_component_execution_proved": False}


def refactor_system(value: dict | str, *, out_dir: str | Path,
                    max_workers: int = 4) -> dict:
    """Inspect and refactor independent Java components in parallel, then gate the result.

    This is intentionally narrower than general architectural modernization: each component must
    expose one supported AST finding (Extract Method or Factory Method), and every worker must
    produce an independent contract-preservation verdict before the aggregate result succeeds.
    """
    try:
        raw = json.loads(value) if isinstance(value, str) else value
        components = raw.get("components", [])
        if not isinstance(components, list) or not components:
            raise ValueError("refactor artifact requires a non-empty components list")
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return _fail("invalid_refactor_artifact", str(exc))
    root = Path(out_dir); root.mkdir(parents=True, exist_ok=True)

    def run(item: dict) -> dict:
        source = Path(item.get("file") or item.get("interface_file") or "")
        if not source.is_file():
            return {"component": item.get("component", source.stem), "status": "FAIL",
                    "code": "source_unavailable", "message": str(source)}
        inspection = inspect_java_file(source)
        findings = inspection.get("findings", [])
        requested = str(item.get("pattern", "")).lower().replace("_", "-")
        finding = next((f for f in findings if f.get("code") == "long-method" and
                        (not requested or requested == "extract-method")), None)
        if finding is None:
            finding = next((f for f in findings if f.get("code") == "conditional-object-creation" and
                            (not requested or requested == "factory-method")), None)
        method = item.get("method") or (finding or {}).get("method")
        if not method and finding and finding.get("code") == "long-method":
            method = re.search(r"Method\s+([A-Za-z_$][\w$]*)", finding.get("message", ""))
            method = method.group(1) if method else None
        if not finding or not method:
            return {"component": item.get("component", source.stem), "status": "FAIL",
                    "code": "no_supported_refactoring_finding", "inspection": inspection}
        pattern = "factory-method" if finding.get("code") == "conditional-object-creation" else "extract-method"
        destination = root / source.name if pattern == "extract-method" else root / source.stem
        inspection_path = root / f"{source.stem}.inspection.json"
        inspection_path.write_text(json.dumps(inspection, indent=2) + "\n", encoding="utf-8")
        transformed = (extract_factory_from_inspection(source, inspection_path, method)
                       if pattern == "factory-method" else
                       extract_method_from_inspection(source, inspection_path, method))
        if transformed.get("status") != "TRANSFORMED":
            return {"component": item.get("component", source.stem), "status": "FAIL",
                    "code": "refactor_transform_failed", "inspection": inspection,
                    "transformation": transformed}
        if pattern == "factory-method":
            destination.mkdir(parents=True, exist_ok=True)
            for name, content in transformed["files"].items():
                (destination / name).write_text(content, encoding="utf-8")
            proof = verify_multifile_contract_refactor(source, destination)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(transformed["source"], encoding="utf-8")
            proof = verify_contract_preserving_refactor(source, destination)
        return {"component": item.get("component", source.stem), "status": proof.get("status"),
                "pattern": pattern, "method": method, "inspection": inspection,
                "proof": proof, "refactored": str(destination)}

    with ThreadPoolExecutor(max_workers=min(max_workers, len(components))) as pool:
        results = list(pool.map(run, components))
    results.sort(key=lambda item: str(item.get("component", "")))
    failed = [item for item in results if item.get("status") != "VERIFIED"]
    if failed:
        return {"status": "SYSTEM_REFACTOR_FAILED", "claim": "NO_PROOF",
                "components": results, "global_behavior_equivalence_proved": False,
                "concurrent_component_execution_proved": False}
    composition = None
    if raw.get("composition") is not None:
        from .composition_render import verify_composition
        composition = verify_composition(raw["composition"])
        if composition.get("status") != "COMPOSITION_VERIFIED":
            return {"status": "SYSTEM_REFACTOR_FAILED", "claim": "NO_PROOF",
                    "code": "composition_verification_failed", "components": results,
                    "composition": composition,
                    "global_behavior_equivalence_proved": False,
                    "concurrent_component_execution_proved": False}
    return {"status": "SYSTEM_REFACTOR_VERIFIED",
            "claim": "SYSTEM_COMPOSITION_PROOF" if composition else
                     "SYSTEM_REFACTOR_CONTRACTS_PRESERVED", "components": results,
            "composition": composition,
            "global_behavior_equivalence_proved": False,
            "concurrent_component_execution_proved": False}


def _fail(code: str, message: str) -> dict:
    return {"status": "SYSTEM_SYNTHESIS_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message,
            "concurrent_component_execution_proved": False}
