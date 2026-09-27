# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `5fd8a421f6acf1bac03f87a61545b6b0ca39325cba522570c3561402fc18b5ca`
- `command_inventory.json` SHA-256: `763e8783b53882899e1c38c8b870437a0e9ed71c07f861fc5fcf0bb7084c78f4`
- `mcp_capabilities.json` SHA-256: `c1503566f843a13c2bb110b1f332f9c5c8578f37ac2c4a03f48762e099e23f74`
- Parsed HTML element IDs: 9
- Same-page fragment links checked: 8
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, and the archived `91c6790` guide
- Unexpected relative assets: none
- Handwritten Java verification and apply-refactor payloads validated through application request models

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
