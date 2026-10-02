# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Read-authorized, bounded V2 candidate preparation. No validation/proof claim.

This internal stage is not an admitted workflow. It performs no traversal,
external execution, provider calls or publication. The caller must separately
authorize those stages and bind their evidence to the returned captured bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

import yaml

from .bounded_inputs import CaptureBudget, capture, input_directory, input_path
from .domain_v2 import DomainSpecV2
from .domain_v2_promotion import candidate_sha256
from .domain_v2_tla import render_v2_tla
from .isolated_tlc import TlcModelRequest
from .workflow_contracts import WorkflowContext


DOMAIN_PREPARATION_LIMITS = {
    "max_input_bytes": 1024**2, "max_input_files": 1, "max_path_depth": 32,
    "max_yaml_nodes": 8192, "max_yaml_depth": 48, "max_scalar_chars": 4096,
    "max_integer_chars": 64, "max_generated_bytes": 2 * 1024**2,
}


@dataclass(frozen=True)
class DomainPreparationRequest:
    candidate_path: str

    def __post_init__(self):
        if (not isinstance(self.candidate_path, str) or not self.candidate_path
                or "\0" in self.candidate_path):
            raise ValueError("candidate_path must be a nonempty path")

    def required_effects(self) -> tuple[str, ...]:
        return ("workspace_read",)


@dataclass(frozen=True)
class CapturedDomainCandidate:
    source_path: str
    source_bytes: bytes
    effective_limits: tuple[tuple[str, int], ...]

    def identity(self) -> dict:
        return {"path": self.source_path, "size": len(self.source_bytes),
                "sha256": hashlib.sha256(self.source_bytes).hexdigest()}


@dataclass(frozen=True)
class PreparedDomainCandidate:
    # Immutable bytes/text only: do not hand later stages a mutable Pydantic
    # object whose nested lists can diverge from its captured identity.
    source_path: str
    source_bytes: bytes
    candidate_json: str
    candidate_sha256: str
    model: TlcModelRequest
    effective_limits: tuple[tuple[str, int], ...]

    def summary(self) -> dict:
        models = {self.model.module_name + ".tla": self.model.tla,
                  self.model.module_name + ".cfg": self.model.cfg}
        return {
            "status": "DOMAIN_MODEL_PREPARED", "claim": "NO_PROOF",
            "validation_performed": False, "review_status": json.loads(self.candidate_json)["review_status"],
            "source": {"path": self.source_path, "size": len(self.source_bytes),
                       "sha256": hashlib.sha256(self.source_bytes).hexdigest()},
            "candidate_sha256": self.candidate_sha256,
            "preparation_limits": dict(self.effective_limits),
            "generated_models": {name: {"size": len(text.encode("utf-8")),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
                for name, text in models.items()},
            "claim_limits": ["preparation_only", "no_traversal_or_tlc_execution",
                             "no_source_correspondence", "no_review_or_promotion"],
        }


def _limits(context: WorkflowContext) -> dict[str, int]:
    limits = {}
    for name, ceiling in DOMAIN_PREPARATION_LIMITS.items():
        value = context.resource_budget.get(name, ceiling)
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        limits[name] = min(value, ceiling)
    return limits


def _parse_candidate(content: bytes, limits: dict[str, int]) -> dict:
    """Apply composition limits before SafeLoader constructs Python objects.

    JSON is a supported YAML subset. Aliases (including cycles), duplicate
    keys, merge keys, multiple documents and non-core tags fail closed.
    """
    class CandidateLoader(yaml.SafeLoader):
        nodes = 0
        depth = 0

        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise ValueError("candidate YAML aliases are not supported")
            if self.nodes >= limits["max_yaml_nodes"]:
                raise ValueError("candidate YAML node allowance exceeded")
            if self.depth >= limits["max_yaml_depth"]:
                raise ValueError("candidate YAML depth allowance exceeded")
            event = self.peek_event()
            if isinstance(event, yaml.ScalarEvent) and len(event.value) > limits["max_scalar_chars"]:
                raise ValueError("candidate scalar allowance exceeded")
            self.nodes += 1
            self.depth += 1
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_object(self, node, deep=False):
            # Reject timestamps, binary blobs, floats (including NaN/Inf), sets
            # and user tags before constructing them. V2 has no float fields.
            allowed = {"str", "int", "bool", "null", "seq", "map"}
            if node.tag not in {"tag:yaml.org,2002:" + tag for tag in allowed}:
                raise ValueError("unsupported candidate YAML tag")
            if isinstance(node, yaml.ScalarNode):
                numeric_text = node.value.lstrip("+-").replace("_", "")
                if ((node.tag.endswith(":int") or numeric_text.isdecimal())
                        and len(node.value) > limits["max_integer_chars"]):
                    raise ValueError("candidate integer allowance exceeded")
            return super().construct_object(node, deep=deep)

        def construct_mapping(self, node, deep=False):
            if not isinstance(node, yaml.MappingNode):
                raise ValueError("candidate mappings must be objects")
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise ValueError("candidate mapping keys must be strings")
                if key in result:
                    raise ValueError("duplicate candidate mapping key")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    loader = CandidateLoader(content.decode("utf-8"))
    try:
        value = loader.get_single_data()
    finally:
        loader.dispose()
    if not isinstance(value, dict):
        raise ValueError("candidate must be an object")
    return value


def capture_domain_candidate(request: DomainPreparationRequest,
                             context: WorkflowContext) -> CapturedDomainCandidate:
    """Retain captured identity even if a subsequent preparation gate fails."""
    context.require("workspace_read")
    limits = _limits(context)
    _, relative = input_path(request.candidate_path, context)
    if len(relative.parts) > limits["max_path_depth"]:
        raise ValueError("candidate path depth allowance exceeded")
    with input_directory(relative, context) as directory:
        content = capture(relative.name, directory, context,
                          CaptureBudget(limits["max_input_bytes"], 1))
    return CapturedDomainCandidate(relative.as_posix(), content, tuple(sorted(limits.items())))


def prepare_captured_domain_candidate(captured: CapturedDomainCandidate) -> PreparedDomainCandidate:
    """Pure internal stage over a previously authorized immutable capture."""
    content, limits = captured.source_bytes, dict(captured.effective_limits)
    try:
        value = _parse_candidate(content, limits)
        candidate = DomainSpecV2.model_validate(value)
        canonical = candidate.model_dump_json()
        # The renderer repeats state names in UNCHANGED lists across actions.
        # Bound that cross-product before allocation. This conservative estimate
        # may reject large valid models; it does not change their semantics.
        expansion = (24 * len(canonical.encode("utf-8"))
            + 12 * (len(candidate.operations) + 1)
                * sum(len(state.name) + 6 for state in candidate.state_variables)
            + 4096 * (len(candidate.operations) + 1))
        if expansion > limits["max_generated_bytes"]:
            raise ValueError("candidate rendering expansion allowance exceeded")
        # Validate module identity before rendering; preserve the original name
        # and existing semantic digest instead of silently renaming the model.
        TlcModelRequest(candidate.domain_name, "", "")
        tla, cfg = render_v2_tla(candidate)
        if len(tla.encode("utf-8")) + len(cfg.encode("utf-8")) > limits["max_generated_bytes"]:
            raise ValueError("generated candidate model allowance exceeded")
        return PreparedDomainCandidate(captured.source_path, content, canonical,
            candidate_sha256(candidate), TlcModelRequest(candidate.domain_name, tla, cfg),
            tuple(sorted(limits.items())))
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("candidate parsing failed within the supported YAML boundary") from exc


def prepare_domain_candidate(request: DomainPreparationRequest,
                             context: WorkflowContext) -> PreparedDomainCandidate:
    """Capture once, then parse/render without reopening the caller's path."""
    return prepare_captured_domain_candidate(capture_domain_candidate(request, context))
