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


def _fail(code: str, message: str) -> dict:
    return {"status": "SYSTEM_SYNTHESIS_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message,
            "concurrent_component_execution_proved": False}
