# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Typed application contracts shared by CLI and MCP adapters.

The adapters may present or transport a workflow differently, but they must
agree on defaults, language/backend selection and required effects before the
application service is entered.  Contexts carry attenuated authority; child
stages cannot recover an effect that their parent did not grant.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from .capability_registry import MCP_EFFECTS
from .mcp_policy import MCPPolicyViolation


WORKFLOW_CONTRACT_SCHEMA = "formalspecgen-workflow-contract-v1"
WORKFLOW_RESULT_SCHEMA = "formalspecgen-workflow-result-v1"


class WorkflowContractError(ValueError):
    """A request cannot be represented by the shared workflow contract."""


class WorkflowInterface(str, Enum):
    CLI = "cli"
    MCP = "mcp"


class EffectAuthority(Protocol):
    def permits(self, effect: str) -> bool: ...
    def summary(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class FixedEffectAuthority:
    """Explicit local authority used by the CLI application adapter.

    This is not an MCP admission and is never serialized as one.  It merely
    prevents shared services from bypassing their declared effect plan.
    """

    effects: tuple[str, ...]

    def permits(self, effect: str) -> bool:
        return effect in self.effects

    def summary(self) -> dict[str, Any]:
        return {"kind": "cli-explicit-effects", "granted_effects": list(self.effects)}


@dataclass(frozen=True)
class AttenuatedEffectAuthority:
    """A child grant that retains the parent policy provenance."""

    parent: EffectAuthority
    effects: tuple[str, ...]

    def permits(self, effect: str) -> bool:
        return effect in self.effects and self.parent.permits(effect)

    def summary(self) -> dict[str, Any]:
        return {
            "kind": "attenuated-workflow-authority",
            "granted_effects": list(self.effects),
            "parent": self.parent.summary(),
        }


def _normalized_effects(effects: tuple[str, ...]) -> tuple[str, ...]:
    unknown = sorted(set(effects) - MCP_EFFECTS)
    if unknown:
        raise WorkflowContractError(
            "unknown workflow effects: " + ", ".join(unknown))
    return tuple(sorted(set(effects)))


@dataclass(frozen=True)
class WorkflowContext:
    """Permission-carrying context passed to application workflow stages."""

    interface: WorkflowInterface
    authority: EffectAuthority
    workspace_root: Path
    required_effects: tuple[str, ...]
    output_root: Path | None = None
    resource_budget: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized = _normalized_effects(self.required_effects)
        object.__setattr__(self, "required_effects", normalized)
        root = self.workspace_root.resolve()
        object.__setattr__(self, "workspace_root", root)
        budget = dict(self.resource_budget)
        if any(not isinstance(value, int) or value < 0 for value in budget.values()):
            raise WorkflowContractError(
                "workflow resource budgets must be non-negative integers")
        object.__setattr__(self, "resource_budget", MappingProxyType(budget))
        missing = [effect for effect in normalized if not self.authority.permits(effect)]
        if missing:
            raise MCPPolicyViolation(
                "workflow authority is missing required effects: " + ", ".join(missing))

    @classmethod
    def for_cli(
            cls, required_effects: tuple[str, ...], *,
            workspace_root: Path | None = None,
            output_root: Path | None = None) -> "WorkflowContext":
        effects = _normalized_effects(required_effects)
        return cls(
            WorkflowInterface.CLI, FixedEffectAuthority(effects),
            (workspace_root or Path.cwd()), effects, output_root)

    @classmethod
    def for_mcp(
            cls, authority: EffectAuthority, required_effects: tuple[str, ...], *,
            workspace_root: Path | None = None,
            output_root: Path | None = None,
            resource_budget: Mapping[str, int] | None = None) -> "WorkflowContext":
        return cls(
            WorkflowInterface.MCP, authority, (workspace_root or Path.cwd()),
            required_effects, output_root, resource_budget or {})

    def require(self, effect: str) -> None:
        if effect not in MCP_EFFECTS:
            raise MCPPolicyViolation(f"unknown workflow effect boundary: {effect}")
        if effect not in self.required_effects or not self.authority.permits(effect):
            raise MCPPolicyViolation(
                f"workflow context does not authorize {effect}")

    def child(self, effects: tuple[str, ...]) -> "WorkflowContext":
        """Return a context with a strict subset of this stage's authority."""
        narrowed = _normalized_effects(effects)
        if not set(narrowed).issubset(self.required_effects):
            raise MCPPolicyViolation("child workflow cannot widen parent authority")
        return WorkflowContext(
            self.interface, AttenuatedEffectAuthority(self.authority, narrowed),
            self.workspace_root,
            narrowed, self.output_root, dict(self.resource_budget))

    def resolve_input(self, value: str | Path, *, must_exist: bool = True) -> Path:
        self.require("workspace_read")
        supplied = Path(value).expanduser()
        path = ((self.workspace_root / supplied).resolve()
                if not supplied.is_absolute() else supplied.resolve())
        if path != self.workspace_root and self.workspace_root not in path.parents:
            raise WorkflowContractError("path must remain inside the current workspace")
        if must_exist and not path.exists():
            raise FileNotFoundError(str(path))
        return path

    def summary(self) -> dict[str, Any]:
        return {
            "interface": self.interface.value,
            "required_effects": list(self.required_effects),
            "authority": self.authority.summary(),
            "workspace_root": str(self.workspace_root),
            "output_root": str(self.output_root) if self.output_root else None,
            "resource_budget": dict(self.resource_budget),
        }


def _source_language(source: str) -> str:
    suffix = Path(source).suffix.lower()
    return {
        ".java": "java", ".jml": "jml", ".rs": "rust", ".c": "c",
        ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    }.get(suffix, suffix.lstrip(".") or "unknown")


@dataclass(frozen=True)
class VerificationWorkflowRequest:
    source: str
    mode: str = "esc"
    backend: str = "prusti"
    result_export: str | None = None
    language: str = field(init=False)
    effective_backend: str = field(init=False)

    def __post_init__(self) -> None:
        source = str(Path(self.source).expanduser().resolve())
        mode = self.mode.strip().lower()
        backend = (self.backend or "prusti").strip().lower()
        if mode not in {"parse", "check", "esc"}:
            raise WorkflowContractError(f"unsupported verification mode: {self.mode}")
        if backend not in {"prusti", "kani"}:
            raise WorkflowContractError(f"unsupported Rust backend: {self.backend}")
        language = _source_language(source)
        effective = {
            "java": "openjml", "jml": "openjml", "c": "frama-c",
            "cpp": "esbmc",
        }.get(language, (backend if mode == "esc" else "rustc")
              if language == "rust" else "unknown")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "backend", backend)
        object.__setattr__(self, "language", language)
        object.__setattr__(self, "effective_backend", effective)

    def required_effects(self, interface: WorkflowInterface) -> tuple[str, ...]:
        effects = ["workspace_read"]
        if not (self.language in {"c", "cpp"} and self.mode != "esc"):
            effects.append("external_execution")
        if interface is WorkflowInterface.MCP:
            effects.append("evidence_publication")
        if self.result_export:
            effects.append("workspace_write_new")
        return _normalized_effects(tuple(effects))

    def as_dict(self) -> dict[str, Any]:
        return {"schema": WORKFLOW_CONTRACT_SCHEMA, "workflow": "verify", **asdict(self)}


@dataclass(frozen=True)
class InspectionWorkflowRequest:
    source: str
    result_export: str | None = None
    language: str = field(init=False)
    mode: str = field(default="inspect", init=False)
    effective_backend: str = field(default="builtin-java-inspector", init=False)

    def __post_init__(self) -> None:
        source = str(Path(self.source).expanduser().resolve())
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "language", _source_language(source))

    def required_effects(self, _interface: WorkflowInterface) -> tuple[str, ...]:
        effects = ["workspace_read"]
        if self.result_export:
            effects.append("workspace_write_new")
        return _normalized_effects(tuple(effects))

    def as_dict(self) -> dict[str, Any]:
        return {"schema": WORKFLOW_CONTRACT_SCHEMA, "workflow": "inspect", **asdict(self)}


@dataclass(frozen=True)
class DocumentationWorkflowRequest:
    source: str
    out: str
    project_root: str = "."
    no_llm: bool = False
    provider: str | None = "ollama"
    model: str | None = None
    result_export: str | None = None
    language: str = field(init=False)
    mode: str = field(init=False)
    effective_backend: str = field(default="builtin-documentation", init=False)

    def __post_init__(self) -> None:
        source = str(Path(self.source).expanduser().resolve())
        language = _source_language(source)
        provider = None if self.no_llm else (self.provider or "ollama").strip().lower()
        if provider not in {None, "glm", "openai", "ollama"}:
            raise WorkflowContractError(f"unsupported documentation provider: {provider}")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "language", language)
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "model", None if self.no_llm else self.model)
        object.__setattr__(self, "mode", "deterministic" if self.no_llm else "provider-assisted")

    def required_effects(self, _interface: WorkflowInterface) -> tuple[str, ...]:
        effects = ["workspace_read", "workspace_write_new"]
        if self.provider is not None:
            effects.append("provider_access")
        return _normalized_effects(tuple(effects))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": WORKFLOW_CONTRACT_SCHEMA,
            "workflow": "document-code",
            **asdict(self),
        }


@dataclass(frozen=True)
class RefactorWorkflowRequest:
    """One baseline/candidate preservation request shared by CLI and MCP.

    ``signing_intent`` records that a caller wants a detached human signature;
    it deliberately carries no key identifier or signing authority.  The
    strict MCP adapter returns an approval-required result for that variant.
    """

    baseline: str
    refactored: str
    result_export: str | None = None
    signing_intent: bool = False
    language: str = field(init=False)
    mode: str = field(default="preserve", init=False)
    effective_backend: str = field(init=False)

    def __post_init__(self) -> None:
        baseline = str(Path(self.baseline).expanduser().resolve())
        refactored = str(Path(self.refactored).expanduser().resolve())
        language = _source_language(baseline)
        effective = {
            "java": "openjml", "jml": "openjml", "rust": "prusti",
            "c": "frama-c", "cpp": "esbmc",
        }.get(language, "unknown")
        object.__setattr__(self, "baseline", baseline)
        object.__setattr__(self, "refactored", refactored)
        object.__setattr__(self, "language", language)
        object.__setattr__(self, "effective_backend", effective)

    def required_effects(self, interface: WorkflowInterface) -> tuple[str, ...]:
        effects = ["workspace_read", "external_execution"]
        if interface is WorkflowInterface.MCP:
            effects.append("evidence_publication")
        if self.result_export:
            effects.append("workspace_write_new")
        return _normalized_effects(tuple(effects))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": WORKFLOW_CONTRACT_SCHEMA,
            "workflow": "verify-refactor",
            **asdict(self),
        }


WorkflowRequest = (
    VerificationWorkflowRequest | InspectionWorkflowRequest |
    DocumentationWorkflowRequest | RefactorWorkflowRequest
)


@dataclass(frozen=True)
class WorkflowResultEnvelope:
    """Typed cross-interface view layered over compatible result payloads."""

    workflow: str
    interface: WorkflowInterface
    request: Mapping[str, Any]
    workflow_status: str
    verification: Mapping[str, Any]
    admission: Mapping[str, Any] | None
    execution: Mapping[str, Any] | None
    publication: Mapping[str, Any] | None
    approval: Mapping[str, Any] | None

    @classmethod
    def from_payload(
            cls, request: WorkflowRequest, interface: WorkflowInterface,
            payload: Mapping[str, Any], *,
            context: WorkflowContext | None = None) -> "WorkflowResultEnvelope":
        request_value = request.as_dict()
        is_verification = request_value["workflow"] in {
            "verify", "verify-refactor"}
        return cls(
            workflow=str(request_value["workflow"]), interface=interface,
            request=request_value,
            workflow_status=str(payload.get("status") or payload.get("final_status") or "UNKNOWN"),
            verification={
                "claim": (payload.get("claim", "NO_PROOF")
                          if is_verification else "NO_PROOF"),
                "request_satisfied": (
                    bool(payload.get("request_satisfied", False))
                    if is_verification else False),
            },
            admission=(context.authority.summary()
                       if context and interface is WorkflowInterface.MCP else None),
            execution=(payload.get("execution")
                       if isinstance(payload.get("execution"), Mapping) else None),
            publication=(
                payload.get("publication")
                if isinstance(payload.get("publication"), Mapping)
                else payload.get("evidence")
                if isinstance(payload.get("evidence"), Mapping) else None),
            approval=(payload.get("approval")
                      if isinstance(payload.get("approval"), Mapping) else None),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": WORKFLOW_RESULT_SCHEMA,
            "workflow": self.workflow,
            "interface": self.interface.value,
            "request": dict(self.request),
            "workflow_status": self.workflow_status,
            "verification": dict(self.verification),
            "admission": dict(self.admission) if self.admission else None,
            "execution": dict(self.execution) if self.execution else None,
            "publication": dict(self.publication) if self.publication else None,
            "approval": dict(self.approval) if self.approval else None,
        }


def bind_workflow_result(
        payload: Mapping[str, Any], request: WorkflowRequest,
        interface: WorkflowInterface, *,
        context: WorkflowContext | None = None) -> dict[str, Any]:
    """Preserve legacy fields and add the authoritative typed result view."""
    result = dict(payload)
    result["workflow_result"] = WorkflowResultEnvelope.from_payload(
        request, interface, result, context=context).as_dict()
    return result
