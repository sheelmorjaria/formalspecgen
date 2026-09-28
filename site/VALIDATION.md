# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `eb4c07ff90e6ffe0812f4e7c72dc1f9c9163aa99fb9b300e75d2dd33389a835f`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `c7e182e2a7bb6877850108062ee62c24b37e010254ccb172f6d5438c05bbf5c8`
- `command_inventory.json` SHA-256: `42bab62e30afa72cb8a06374760d91a20704ae3406f12cb7129a314a1ef5e066`
- `mcp_capabilities.json` SHA-256: `fee47d62ff6f1969ee007dbfbf699f832a2cc90e2fcc5400949bdc3174d24431`
- Parsed HTML element IDs: 20
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 204; local links and cross-page fragments checked
- All 42 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 15

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
