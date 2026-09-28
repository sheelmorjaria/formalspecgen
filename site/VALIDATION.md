# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `e3daf41e7d59d150827f5fe0fd594f5de2e0951526586d6dd19b82045572025d`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `f07fee3474b68540d6e4353b50c03e9a2860dc57d348325d8e80c0161f3d991d`
- `command_inventory.json` SHA-256: `d37dfe15e93094e11e7655fbb1e0028520d2707685242088972b062ac6d955a6`
- `mcp_capabilities.json` SHA-256: `23d160cbc1855305c25954f06022c263173565c8673366538367a86d29586ad9`
- Parsed HTML element IDs: 21
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 205; local links and cross-page fragments checked
- All 43 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 16

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
