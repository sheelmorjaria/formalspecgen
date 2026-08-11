# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Generate a fail-closed domain-plugin skeleton from validated YAML or JSON."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_PYTHON_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")
_CLASS_NAME = re.compile(r"^[A-Z][A-Za-z0-9]*$")


class StateVariableSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    type: str
    bound: tuple[int, int]

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not _PYTHON_NAME.fullmatch(value):
            raise ValueError("state-variable names must be safe lower-case identifiers")
        return value

    @field_validator("type")
    @classmethod
    def valid_type(cls, value: str) -> str:
        if value not in {"int", "dict"}:
            raise ValueError("state-variable type must be int or dict")
        return value

    @field_validator("bound")
    @classmethod
    def valid_bound(cls, value: tuple[int, int]) -> tuple[int, int]:
        if value[0] < 0 or value[0] >= value[1] or value[1] > 100:
            raise ValueError("bounds must satisfy 0 <= lower < upper <= 100")
        return value


class OperationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    guards: list[str]
    effect: str
    frame: list[str]
    ast_pattern: str

    @field_validator("name", "effect")
    @classmethod
    def safe_identifier(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("operation/effect must be a safe identifier")
        return value

    @field_validator("guards")
    @classmethod
    def safe_guards(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values) or any(not _PYTHON_NAME.fullmatch(v) for v in values):
            raise ValueError("guards must be unique safe identifiers")
        return values


class DomainSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    review_status: Literal["unreviewed", "reviewed"] = "unreviewed"
    schema_version: Literal[1] = 1
    domain_name: str
    module_name: str
    state_variables: list[StateVariableSpec] = Field(min_length=1)
    operations: list[OperationSpec] = Field(min_length=1)
    tlc_invariants: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_domain(self) -> "DomainSpec":
        if not _CLASS_NAME.fullmatch(self.domain_name):
            raise ValueError("domain_name must be a safe PascalCase identifier")
        if not _PYTHON_NAME.fullmatch(self.module_name):
            raise ValueError("module_name must be a safe lower-case identifier")
        state = [item.name for item in self.state_variables]
        operations = [item.name for item in self.operations]
        if len(set(state)) != len(state) or len(set(operations)) != len(operations):
            raise ValueError("state variables and operations must be unique")
        state_set = set(state)
        for operation in self.operations:
            if not operation.frame or not set(operation.frame) <= state_set:
                raise ValueError(f"{operation.name} frame must reference declared state variables")
            if not operation.ast_pattern.strip():
                raise ValueError(f"{operation.name} requires a documented AST pattern")
            bare_guards = set(operation.guards) & state_set
            if bare_guards:
                raise ValueError(
                    f"{operation.name} guards must be semantic predicates with values, not "
                    f"bare state names: {', '.join(sorted(bare_guards))}")
            if (operation.effect in state_set or
                    operation.effect in {f"set_{name}" for name in state_set}):
                raise ValueError(
                    f"{operation.name} effect must identify the concrete transition, not "
                    f"generic effect {operation.effect!r}")
            if "+/-" in operation.ast_pattern or re.search(r"\w+'\s*=", operation.ast_pattern):
                raise ValueError(
                    f"{operation.name} AST pattern is ambiguous/pseudocode; use exact JML "
                    "post-state expressions and split direction-dependent transitions")
        if len(set(self.tlc_invariants)) != len(self.tlc_invariants) or any(
                not re.fullmatch(r"[A-Z][A-Za-z0-9_]*", item)
                for item in self.tlc_invariants):
            raise ValueError("TLC invariants must be unique safe operator names")
        self._validate_observable_duration(state_set)
        self._validate_binary_door_transitions()
        return self

    def _validate_observable_duration(self, state_set: set[str]) -> None:
        duration_states = {name for name in state_set if re.search(
            r"(?:^|_)(?:moving|motion|transit|in_flight|in_progress|active)(?:_|$)", name)}
        if not duration_states:
            return
        def words(value: str) -> str:
            return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()
        entering = [operation for operation in self.operations if (
            re.search(r"(?:^|_)(?:start|begin)(?:_|$)", words(operation.name)) or
            re.search(r"(?:set|enter).*(?:moving|motion|transit|active)",
                      operation.effect.lower())) and
            bool(set(operation.frame) & duration_states)]
        leaving = [operation for operation in self.operations if (
            re.search(r"(?:^|_)(?:arrive|stop|complete|finish)(?:_|$)",
                      words(operation.name)) or
            re.search(r"(?:clear|leave|stop).*(?:moving|motion|transit|active)",
                      operation.effect.lower())) and
            bool(set(operation.frame) & duration_states)]
        if not entering or not leaving:
            raise ValueError(
                "observable duration state requires separate start/begin and "
                "arrive/stop/complete operations that frame the duration state; otherwise "
                "in-transit safety invariants are vacuous")

    def _validate_binary_door_transitions(self) -> None:
        doors = [item for item in self.state_variables
                 if "door" in item.name and item.bound == (0, 1)]
        if not doors:
            return
        names = [item.name.lower() for item in self.operations]
        if not any("open" in name for name in names) or not any("close" in name for name in names):
            raise ValueError(
                "observable binary door state requires both open and close transitions")


def load_spec(path: Path) -> DomainSpec:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        value = json.loads(raw)
    elif path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("YAML input requires PyYAML; use JSON or install requirements.txt") from exc
        value = yaml.safe_load(raw)
    else:
        raise ValueError("domain specification must use .json, .yaml, or .yml")
    return DomainSpec.model_validate(value)


def _literal(values: list[str]) -> str:
    return "Literal[" + ", ".join(repr(value) for value in values) + "]"


def _ir_source(spec: DomainSpec) -> str:
    operations = [item.name for item in spec.operations]
    guards = sorted({guard for item in spec.operations for guard in item.guards}) or ["no_guard"]
    effects = [item.effect for item in spec.operations]
    frames = [item.name for item in spec.state_variables]
    return f'''"""Generated strict IR for {spec.domain_name}; edit only after review."""
from typing import Literal
from pydantic import BaseModel, ConfigDict
from ..transition_ir import MethodTransitionIR

Operation = {_literal(operations)}
GuardId = {_literal(guards)}
EffectId = {_literal(effects)}
FrameId = {_literal(frames)}

class {spec.domain_name}OperationIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Operation
    guard_ids: list[GuardId]
    effect_id: EffectId
    frame_ids: list[FrameId]
    result_constrained: bool
    failure_preserves_frame: bool

class {spec.domain_name}TlaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    domain: Literal[{spec.module_name!r}] = {spec.module_name!r}
    operations: list[{spec.domain_name}OperationIR]
    transitions: list[MethodTransitionIR]
'''


def _extract_source(spec: DomainSpec) -> str:
    required = [item.name.lower() for item in spec.operations]
    patterns = "\n".join(f"    # - {item.name}: {item.ast_pattern}" for item in spec.operations)
    return f'''"""Generated recognizer and fail-closed adapter skeleton for {spec.domain_name}."""
import re
from ..extract_tla_ir import UnsupportedJmlSemantics
from .{spec.module_name} import {spec.domain_name}TlaModel

REQUIRED_METHODS = {required!r}

def recognizes_{spec.module_name}(code: str) -> bool:
    lowered = code.lower()
    return all(re.search(rf"\\b{{name}}\\s*\\(", lowered) for name in REQUIRED_METHODS)

def extract_{spec.module_name}_model(code: str, clarifications: str, abstraction: str | None):
    del code, clarifications, abstraction
    # Reviewed AST patterns declared by the domain specification:
{patterns}
    # TODO: parse methods with extract_method_transition_ir, structurally match every
    # effect/guard/frame, construct {spec.domain_name}OperationIR values, then return
    # ({spec.domain_name}TlaModel(...), findings).
    raise UnsupportedJmlSemantics(
        "{spec.module_name} plugin is scaffolded but its AST adapter is not reviewed")
'''


def _render_source(spec: DomainSpec) -> str:
    variables = ", ".join(item.name for item in spec.state_variables)
    invariants = "\n".join(f"INVARIANT {item}" for item in spec.tlc_invariants)
    return f'''"""Generated fail-closed renderer skeleton for {spec.domain_name}."""
from ..extract_tla_ir import UnsupportedJmlSemantics
from .{spec.module_name} import {spec.domain_name}TlaModel
from .{spec.module_name}_extract import extract_{spec.module_name}_model, recognizes_{spec.module_name}
from .router import DomainPlugin

STATE_VARIABLES = {variables!r}
CFG_INVARIANTS = {invariants!r}

def render_{spec.module_name}(model: {spec.domain_name}TlaModel) -> tuple[str, str]:
    del model
    # TODO: implement reviewed complete-variable assignments, Init, Next, bounds,
    # invariants, Spec, and separate CFG serialization. Never interpolate AST strings.
    raise UnsupportedJmlSemantics(
        "{spec.module_name} plugin is scaffolded but its TLA+ renderer is not reviewed")

{spec.module_name.upper()}_PLUGIN = DomainPlugin(
    {spec.module_name!r}, recognizes_{spec.module_name},
    extract_{spec.module_name}_model, render_{spec.module_name})
'''


def _test_source(spec: DomainSpec) -> str:
    calls = " ".join(f"void {item.name}() {{}}" for item in spec.operations)
    return f'''import unittest
from pipeline.domains.{spec.module_name}_extract import (
    UnsupportedJmlSemantics, extract_{spec.module_name}_model, recognizes_{spec.module_name})

class {spec.domain_name}DomainTests(unittest.TestCase):
    def test_complete_api_is_recognized(self):
        self.assertTrue(recognizes_{spec.module_name}("class X {{ {calls} }}"))
        self.assertFalse(recognizes_{spec.module_name}("class X {{}}"))

    def test_unreviewed_adapter_fails_closed(self):
        with self.assertRaises(UnsupportedJmlSemantics):
            extract_{spec.module_name}_model("class X {{}}", "", None)

if __name__ == "__main__":
    unittest.main()
'''


def _register(registry: Path, spec: DomainSpec) -> None:
    source = registry.read_text(encoding="utf-8")
    import_line = f"from .{spec.module_name}_render import {spec.module_name.upper()}_PLUGIN"
    plugin_line = f"    {spec.module_name.upper()}_PLUGIN,"
    if import_line not in source:
        source = source.replace("# END SCAFFOLDED IMPORTS",
            import_line + "\n# END SCAFFOLDED IMPORTS")
    if plugin_line not in source:
        source = source.replace("    # END SCAFFOLDED PLUGINS",
            plugin_line + "\n    # END SCAFFOLDED PLUGINS")
    registry.write_text(source, encoding="utf-8")


def scaffold_sources(spec: DomainSpec) -> dict[str, str]:
    """Return reviewed fail-closed scaffold artifacts without touching the filesystem."""
    return {
        f"pipeline/domains/{spec.module_name}.py": _ir_source(spec),
        f"pipeline/domains/{spec.module_name}_extract.py": _extract_source(spec),
        f"pipeline/domains/{spec.module_name}_render.py": _render_source(spec),
        f"tests/test_{spec.module_name}_domain.py": _test_source(spec),
    }


def registration_lines(spec: DomainSpec) -> dict[str, str]:
    return {
        "import": f"from .{spec.module_name}_render import {spec.module_name.upper()}_PLUGIN",
        "plugin": f"    {spec.module_name.upper()}_PLUGIN,",
    }


def scaffold_domain(spec_path: str | Path, *, project_root: str | Path | None = None,
                    force: bool = False, register: bool = True,
                    replace_reviewed: bool = False) -> list[Path]:
    spec = load_spec(Path(spec_path))
    root = Path(project_root) if project_root else Path(__file__).resolve().parent.parent
    canonical = root / "domains" / f"{spec.module_name}.yaml"
    if canonical.exists():
        existing_spec = load_spec(canonical)
        if existing_spec.review_status == "reviewed" and not replace_reviewed:
            raise PermissionError(
                f"refusing to replace reviewed domain {spec.module_name!r}; "
                "use --replace-reviewed-domain only after explicit human review")
    domain_dir, tests_dir = root / "pipeline" / "domains", root / "tests"
    domain_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)
    outputs = {root / relative: source for relative, source in scaffold_sources(spec).items()}
    existing = [path for path in outputs if path.exists()]
    if existing and not force:
        raise FileExistsError("refusing to overwrite: " + ", ".join(map(str, existing)))
    for path, source in outputs.items():
        path.write_text(source, encoding="utf-8")
    if register:
        registry = domain_dir / "registry.py"
        if not registry.exists():
            raise FileNotFoundError(f"plugin registry is missing: {registry}")
        _register(registry, spec)
    return list(outputs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--replace-reviewed-domain", action="store_true")
    parser.add_argument("--no-register", action="store_true")
    args = parser.parse_args()
    paths = scaffold_domain(args.spec, force=args.force, register=not args.no_register,
                            replace_reviewed=args.replace_reviewed_domain)
    print("Scaffolded:\n" + "\n".join(f"- {path}" for path in paths))
    print("The plugin is registered but fails closed until its AST adapter and renderer TODOs are reviewed.")


if __name__ == "__main__":
    main()
