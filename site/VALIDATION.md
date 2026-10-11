# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `50c1e25704343e690b95ca09a4cee868cab5f0e9e2d7056d8bcc7d69766e8826`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `5fb4dec6d02c797eef92f01e723752e52aae726d312557502b749db0ffacb871`
- `command_inventory.json` SHA-256: `a174ca3c22ae57b2bcb543e851e115c7674a42d3da6afd8602b064611a52e5e9`
- `mcp_capabilities.json` SHA-256: `2ae0a3c492c6c8366c53751378b8fb0d8c74090ca13a238827ea24207122f684`
- Parsed HTML element IDs: 24
- Same-page fragment links checked: 19
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 206; local links and cross-page fragments checked
- All 44 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 20

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
