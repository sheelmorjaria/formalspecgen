# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `09c6105bca06fba37891896d9ee47aa7ce7d72bb542303e9425010feadf02121`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `a605e62054390251d99b4b5712b9b807b3b0a8a191a2ffb577db5106f96fbdb8`
- `command_inventory.json` SHA-256: `7ed88bdb0a5507f63a2d8914a87f0a8cede00a4840b68d2f997f98d722a9b619`
- `mcp_capabilities.json` SHA-256: `a3eb056522e96a4e610ab102c291ddec135ec4d18c92f9c3a17def462c028afc`
- Parsed HTML element IDs: 14
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 200; local links and cross-page fragments checked
- All 38 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 6

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
