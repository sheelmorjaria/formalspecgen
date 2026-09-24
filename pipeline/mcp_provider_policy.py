# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Server-controlled provider and model selection for strict MCP workflows."""

from __future__ import annotations

import os

from . import config
from .mcp_policy import MCPPolicyViolation


def _default_models() -> dict[str, str]:
    return {
        "glm": config.GLM_MODEL,
        "openai": config.OPENAI_MODEL,
        "ollama": config.OLLAMA_MODEL,
    }


def _extra_models() -> dict[str, set[str]]:
    """Parse trusted ``provider:model`` entries from the server environment."""
    result: dict[str, set[str]] = {}
    raw = os.environ.get("FORMALSPECGEN_MCP_DOCUMENT_MODELS", "")
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        provider, separator, model = entry.partition(":")
        if not separator or provider not in _default_models() or not model.strip():
            raise MCPPolicyViolation(
                "FORMALSPECGEN_MCP_DOCUMENT_MODELS must contain provider:model entries")
        result.setdefault(provider, set()).add(model.strip())
    return result


def resolve_documentation_model(provider: str, requested: str | None) -> str:
    """Resolve a model without allowing request data to select an arbitrary model."""
    defaults = _default_models()
    if provider not in defaults:
        raise MCPPolicyViolation(f"documentation provider is not approved: {provider}")
    selected = requested or defaults[provider]
    allowed = {defaults[provider], *_extra_models().get(provider, set())}
    if selected not in allowed:
        raise MCPPolicyViolation(
            f"documentation model is not approved for {provider}: {selected}")
    return selected
