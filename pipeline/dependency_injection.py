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

_AWS_RUST_PROMPT = """Implement this generated Rust external adapter stub with the AWS SDK.

Rules:
- Return exactly one complete Rust source file in a ```rust fence and no prose.
- Preserve the struct name, the `impl Trait for Struct` clause, every method
  signature, and every #[requires]/#[ensures] Prusti attribute exactly.
- Preserve the first-line marker `// UNVERIFIED EXTERNAL BOUNDARY`.
- Fill only method bodies with realistic aws-sdk-s3 (or aws-sdk-*) calls in an
  sdk-injected body; network behavior remains unverified.
- Do not add unsafe code, unwrap, expect, panic paths, or weaken any contract.
"""

_CURL_CPP_PROMPT = """Implement this generated C++ external adapter stub with libcurl.

Rules:
- Return exactly one complete C++17 source file in a ```cpp fence and no prose.
- Preserve the class name, base interface, every method signature, and every
  assertion-based contract check exactly.
- Preserve the first-line marker `// UNVERIFIED EXTERNAL BOUNDARY`.
- Fill only method bodies with libcurl transfers (`#include <curl/curl.h>`); network
  behavior remains unverified.
- Do not add exceptions, raw new/delete, or weaken any contract.
"""

# dependency -> (suffix set, language, prompt)
_POLYGLOT_DEPENDENCIES = {
    "aws": {".rs": ("rust", _AWS_RUST_PROMPT)},
    "curl": {".cpp": ("cpp", _CURL_CPP_PROMPT), ".cc": ("cpp", _CURL_CPP_PROMPT),
             ".cxx": ("cpp", _CURL_CPP_PROMPT)},
}

_ADAPTER_SHAPES = {
    "rust": re.compile(r"\bimpl\s+[A-Za-z_][\w]*\s+for\s+([A-Za-z_][\w]*)"),
    "cpp": re.compile(r"\bclass\s+([A-Za-z_]\w*)\s*:\s*public\s+[A-Za-z_]\w*"),
}


def inject_dependency(source: str | Path, dependency: str, *, provider: str = "ollama",
                      model: str | None = None) -> dict:
    path = Path(source)
    original = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    language = None
    prompt = None
    if dependency == "stripe":
        if suffix not in {".java", ".jml"}:
            return _fail("unsupported_dependency",
                         f"dependency {dependency!r} only supports .java adapters")
    elif dependency in _POLYGLOT_DEPENDENCIES:
        lane = _POLYGLOT_DEPENDENCIES[dependency].get(suffix)
        if lane is None:
            return _fail("unsupported_dependency",
                         f"dependency {dependency!r} does not support {suffix!r} adapters")
        language, prompt = lane
    else:
        return _fail("unsupported_dependency", f"unsupported dependency {dependency!r}")
    if "UNVERIFIED EXTERNAL BOUNDARY" not in original:
        return _fail("not_external_adapter", "source is not a generated external adapter")
    if language is None:
        class_name = re.search(r"\bclass\s+([A-Za-z_$][\w$]*)\s+implements\s+", original)
        if not class_name:
            return _fail("adapter_surface_unrecognized",
                         "adapter class/implements surface is missing")
        adapter_name = class_name.group(1)
        system_prompt = _STRIPE_PROMPT
    else:
        shape = _ADAPTER_SHAPES[language].search(original)
        if not shape:
            return _fail("adapter_surface_unrecognized",
                         f"{language} adapter implementation surface is missing")
        adapter_name = shape.group(1)
        system_prompt = prompt
    try:
        response = _chat_fn(provider)([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": original},
        ], model, 0.1)
        raw = response[0] if isinstance(response, tuple) else response
        candidate = strip_fence(raw)
    except LLMError as exc:
        return _fail("provider_error", f"LLM provider failed [{exc.code}]: {exc}")
    if "UNVERIFIED EXTERNAL BOUNDARY" not in candidate:
        return _fail("boundary_marker_removed", "generated adapter removed the external-boundary marker")
    if language is None:
        same_surface, differences = trusted_surface_matches(original, candidate)
    else:
        from .polyglot_implementation import (
            trusted_surface_matches as polyglot_surface_matches)
        same_surface, differences = polyglot_surface_matches(original, candidate, language)
    if not same_surface:
        return _fail("adapter_surface_changed", "generated adapter changed its trusted surface",
                     {"differences": differences})
    path.write_text(candidate, encoding="utf-8")
    verdict = {"status": "INJECTED", "claim": "UNVERIFIED_EXTERNAL_ADAPTER",
               "dependency": dependency, "adapter": adapter_name,
               "external_io_safety_proved": False, "source": str(path.resolve()),
               "implementation_code": candidate}
    if language is not None:
        verdict["language"] = language
    return verdict


def _fail(code: str, message: str, extra: dict | None = None) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "external_io_safety_proved": False, **(extra or {})}
