# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Provider-backed implementations for explicitly unverified external adapters."""
from __future__ import annotations

import re
from pathlib import Path

from .implementation import trusted_surface_matches
from .llm import LLMError, _chat_fn, strip_fence


class DependencyInjectionError(ValueError):
    """An adapter dependency request could not be safely applied."""


_STRIPE_PROMPT = """Implement this generated Java Stripe adapter stub.

Rules:
- Return exactly one complete Java file in a ```java fence and no prose.
- Preserve the class name, implements clause, method signatures, and every JML clause exactly.
- Preserve the first-line marker `// UNVERIFIED EXTERNAL BOUNDARY`.
- Fill only method bodies with realistic Stripe API calls; network behavior remains unverified.
- Do not add assumptions, weaken contracts, or modify the public/JML surface.
Use the project's configured Stripe SDK conventions, and keep the result deterministic and readable.
"""


def inject_dependency(source: str | Path, dependency: str, *, provider: str = "ollama",
                      model: str | None = None) -> dict:
    path = Path(source)
    original = path.read_text(encoding="utf-8")
    if dependency != "stripe":
        return _fail("unsupported_dependency", f"unsupported dependency {dependency!r}")
    if "UNVERIFIED EXTERNAL BOUNDARY" not in original:
        return _fail("not_external_adapter", "source is not a generated external adapter")
    class_name = re.search(r"\bclass\s+([A-Za-z_$][\w$]*)\s+implements\s+", original)
    if not class_name:
        return _fail("adapter_surface_unrecognized", "adapter class/implements surface is missing")
    try:
        response = _chat_fn(provider)([
            {"role": "system", "content": _STRIPE_PROMPT},
            {"role": "user", "content": original},
        ], model, 0.1)
        raw = response[0] if isinstance(response, tuple) else response
        candidate = strip_fence(raw)
    except LLMError as exc:
        return _fail("provider_error", f"LLM provider failed [{exc.code}]: {exc}")
    if "UNVERIFIED EXTERNAL BOUNDARY" not in candidate:
        return _fail("boundary_marker_removed", "generated adapter removed the external-boundary marker")
    same_surface, differences = trusted_surface_matches(original, candidate)
    if not same_surface:
        return _fail("adapter_surface_changed", "generated adapter changed its trusted surface",
                     {"differences": differences})
    path.write_text(candidate, encoding="utf-8")
    return {"status": "INJECTED", "claim": "UNVERIFIED_EXTERNAL_ADAPTER",
            "dependency": dependency, "adapter": class_name.group(1),
            "external_io_safety_proved": False, "source": str(path.resolve()),
            "implementation_code": candidate}


def _fail(code: str, message: str, extra: dict | None = None) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "external_io_safety_proved": False, **(extra or {})}
