# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic native lock scaffolds and exact structural-discipline evidence."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .domain_v2 import (
    BinaryExpr, BooleanExpr, BoolStateVariable, FieldExpr, IntegerExpr, NotExpr, OldExpr,
)
from .domain_v2_promotion import ReviewedDomainSpecV2


class UnsupportedLockSerialization(ValueError):
    pass


def _rust_expr(node, fields: dict[str, str]) -> str:
    if isinstance(node, FieldExpr):
        return fields.get(node.name, f"state.{node.name}")
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return _rust_expr(node.expression, fields)
    if isinstance(node, NotExpr):
        return f"!({_rust_expr(node.expression, fields)})"
    if isinstance(node, BinaryExpr):
        left, right = _rust_expr(node.left, fields), _rust_expr(node.right, fields)
        if node.kind == "implies":
            return f"(!({left}) || ({right}))"
        operators = {"eq": "==", "neq": "!=", "lt": "<", "lte": "<=",
                     "gt": ">", "gte": ">=", "add": "+", "sub": "-",
                     "and": "&&", "or": "||"}
        return f"({left} {operators[node.kind]} {right})"
    raise UnsupportedLockSerialization(f"unsupported lock expression {type(node).__name__}")


def _without_outer_parentheses(value: str) -> str:
    return value[1:-1] if value.startswith("(") and value.endswith(")") else value


def render_rust_mutex(reviewed: ReviewedDomainSpecV2) -> str:
    """Render one non-panicking mutex around every concrete domain field."""
    metadata = reviewed.concurrency
    if metadata is None or metadata.linearization_points is None:
        raise UnsupportedLockSerialization("complete lock protocol metadata is required")
    concrete = [item for item in reviewed.state_variables
                if item.name != metadata.lock_variable]
    if not concrete:
        raise UnsupportedLockSerialization("lock protocol requires concrete protected state")
    lines = [
        "use std::sync::Mutex;", "",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        "pub enum LockError {", "    Poisoned,", "    Unavailable,", "}", "",
        f"struct {reviewed.domain_name}State {{",
    ]
    for variable in concrete:
        kind = "bool" if isinstance(variable, BoolStateVariable) else "i32"
        lines.append(f"    {variable.name}: {kind},")
    lines.extend(["}", "", f"pub struct {reviewed.domain_name} {{",
                  f"    state: Mutex<{reviewed.domain_name}State>,", "}", "",
                  f"impl {reviewed.domain_name} {{",
                  "    /// Creates the reviewed initial state.",
                  "    pub fn new() -> Self {",
                  "        Self {", "            state: Mutex::new(" +
                  f"{reviewed.domain_name}State {{"])
    for variable in concrete:
        initial = (("true" if variable.initial else "false")
                   if isinstance(variable, BoolStateVariable) else str(variable.initial))
        lines.append(f"                {variable.name}: {initial},")
    lines.extend(["            }),", "        }", "    }"])
    for variable in concrete:
        kind = "bool" if isinstance(variable, BoolStateVariable) else "i32"
        lines.extend(["", f"    /// Reads `{variable.name}` while holding the state mutex.",
            f"    pub fn get_{variable.name}(&self) -> Result<{kind}, LockError> {{",
            "        let state = self.state.lock().map_err(|_| LockError::Poisoned)?;",
            f"        Ok(state.{variable.name})", "    }"])
    for operation in reviewed.operations:
        referenced = sorted({name for effect in operation.effects
                             for name in _field_names(effect.value)} -
                            {metadata.lock_variable})
        pre = {name: f"pre_{name}" for name in referenced}
        guards = [_rust_expr(item.expression, {}) for item in operation.guards]
        method = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", operation.name).lower()
        lines.extend(["", f"    /// Executes reviewed operation `{operation.name}` under the mutex.",
            f"    pub fn {method}(&self) -> Result<(), LockError> {{",
            "        let mut state = self.state.lock().map_err(|_| LockError::Poisoned)?;"])
        if guards:
            lines.extend([f"        if !({' && '.join(guards)}) {{",
                          "            return Err(LockError::Unavailable);", "        }"])
        for name in referenced:
            lines.append(f"        let pre_{name} = state.{name};")
        for effect in operation.effects:
            lines.append(f"        state.{effect.target} = "
                         f"{_without_outer_parentheses(_rust_expr(effect.value, pre))};")
        lines.extend(["        Ok(())", "    }"])
    lines.extend(["}", ""])
    return "\n".join(lines)


def _field_names(node) -> set[str]:
    if isinstance(node, FieldExpr):
        return {node.name}
    if isinstance(node, (OldExpr, NotExpr)):
        return _field_names(node.expression)
    if isinstance(node, BinaryExpr):
        return _field_names(node.left) | _field_names(node.right)
    return set()


def lock_discipline_gate(reviewed: ReviewedDomainSpecV2, code: str, language: str) -> dict:
    """Bind exact canonical lock scaffolds without claiming linearizability."""
    if reviewed.concurrency is None:
        return _fail("missing_lock_protocol", "reviewed domain has no lock protocol")
    if language == "java":
        from .v2_jml_serializer import render_class
        expected = render_class(reviewed)
    elif language == "rust":
        expected = render_rust_mutex(reviewed)
    else:
        return _fail("unsupported_language", "lock discipline supports Java and Rust")
    if code != expected:
        return _fail("noncanonical_lock_surface",
                     "source differs from deterministic reviewed lock serialization")
    return {"status": "VERIFIED", "claim": "LOCK_DISCIPLINE_VERIFIED",
            "scope": "canonical_single_mutex_state_access",
            "lock_discipline_proved": True,
            "source_model_refinement_proved": False,
            "source_refinement_proved": False,
            "concurrent_linearizability_proved": False,
            "source_sha256": hashlib.sha256(code.encode()).hexdigest(),
            "disclaimer": "Structural lock discipline is not a history refinement proof."}


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "code": code, "message": message,
            "claim": "NO_PROOF", "lock_discipline_proved": False,
            "source_model_refinement_proved": False,
            "source_refinement_proved": False,
            "concurrent_linearizability_proved": False}


def render_reviewed_rust_mutex_file(path: str | Path) -> tuple[ReviewedDomainSpecV2, str]:
    reviewed = ReviewedDomainSpecV2.model_validate_json(
        Path(path).read_text(encoding="utf-8"))
    return reviewed, render_rust_mutex(reviewed)
