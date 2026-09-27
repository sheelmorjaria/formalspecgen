# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `92e00343a11af07d9e09d81ebda2feed71f00625ee6dc5ad0a3a037df8832078`
- `command_inventory.json` SHA-256: `a2200c1e281b39a155617a4a49d3ba4a7c00a531bd85db051789f664de9c343a`
- `mcp_capabilities.json` SHA-256: `739a870bbf3bb30a0418c67eb2a62e6e1bd9060becbcac81c6132a0f9af32bc8`
- Parsed HTML element IDs: 10
- Same-page fragment links checked: 9
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, and the archived `91c6790` guide
- Unexpected relative assets: none
- Handwritten Java verification, codebase-analysis, and apply-refactor payloads validated through application request models

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
