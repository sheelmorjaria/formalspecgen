# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `84e7b0b75894ca089a6b79b2fcf073715270bdf86247667b361d666abfe6dcc1`
- `command_inventory.json` SHA-256: `0d1e571d414b26f292e642ad75390a5077ba6d8bc94659eb68c57e2af5db1906`
- `mcp_capabilities.json` SHA-256: `af58c45c0111c2f5f4063cbf91c6ec44500ec1f1eb1857fea215a342e3bd2ce4`
- Parsed HTML element IDs: 9
- Same-page fragment links checked: 8
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, and the archived `91c6790` guide
- Unexpected relative assets: none
- Handwritten Java verification payloads validated through the application request model

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
