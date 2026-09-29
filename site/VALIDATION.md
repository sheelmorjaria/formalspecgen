# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `c0166554af547efade4448daf310732a51b6889c7964c5a1d38169a2626eb2d6`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `f9f27ad47dc35a377ab2ef8b469e0c34dcd8986b39e130133e4ce1093e4a0082`
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
