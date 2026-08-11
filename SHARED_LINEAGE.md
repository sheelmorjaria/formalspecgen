# Shared Lineage with formalspecDD

This project originally reused infrastructure from the sibling project `../formalspecDD`.
The implementation-synthesis loop and deterministic postprocessor needed by the product path are
now packaged locally, so the sibling checkout is no longer a runtime dependency:

```
NL ──[formalspecgen]──▶ trusted JML ──[native synthesis + OpenJML ESC]──▶ verified Java
```

## Modules ported from formalspecDD (origin recorded for a future shared-package extraction)

| Module | Origin | Notes |
|---|---|---|
| `pipeline/config.py` | DD `pipeline/config.py` | near-verbatim; added `CHECK_TIMEOUT` |
| `pipeline/schemas.py` | DD `pipeline/schemas.py` | `VC`, `Attempt` ported; added `SpecDraft`, `SpecResult` |
| `pipeline/parse_vcs.py` | DD `pipeline/parse_vcs.py` | verbatim (ESC `verify:` parser; used on the optional deep-check path) |
| `pipeline/strategy.py` | DD `pipeline/strategy.py` | near-verbatim (renamed `spec_defect_suspected`→`ambiguity_suspected`); direction-agnostic loop/stall logic |
| `pipeline/verify.py` | DD `pipeline/verify.py` | generalized: `-esc`-only → `-parse`/`-check`/`-esc` |
| `pipeline/llm.py` | DD `pipeline/llm.py` | transport (`_glm_chat`, `LLMError`, `strip_fence`) ported; prompts rewritten for NL→JML |
| `pipeline/implementation.py` | DD orchestration design | local trusted-contract generation, repair, stall detection, evidence, and proof loop |

## Written fresh for formalspecgen

- `pipeline/parse_check.py` — parses `openjml -check`/`-parse` `error:`/`warning:` output
- `pipeline/jml_io.py` — class-name + JML extraction for the stub artifact
- `pipeline/orchestrator.py` — NL → draft → `-check` → bounded repair loop → verdict
- `pipeline/implementation.py` — trusted JML → Java bodies → `javac` → OpenJML ESC → verdict
- `pipeline/cli.py` — terminal REPL and CI-facing command entry point
- `archive/server.py`, `archive/static/index.html` — retired FastAPI and browser interfaces

## Extracted shared postprocessor

The deterministic transformation library now lives in
`formalspec_core/postprocess.py`. FormalSpecGen imports it statically through the
`pipeline/postprocess.py` compatibility facade, so packaged servers do not require a sibling
checkout. The sibling project can consume the same package by installing this repository or
placing it on `PYTHONPATH`; its existing copy remains unchanged until that repository is migrated.

The retired external handoff implementation, its fixtures, and its tests are preserved under
`archive/formalspecdd-compat/`. They are not packaged or imported by the active CLI.

## Promotion path (later)

If both projects stabilize, extract the shared modules (`config`, `llm` transport,
`verify`, `parse_vcs`, `strategy`, `schemas`) into a `formalspec_common` package both
import, eliminating the current two-copy drift risk. Until then, when fixing a bug in
a shared module here, check whether DD needs the same fix.
