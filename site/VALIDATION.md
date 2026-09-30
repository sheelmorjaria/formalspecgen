# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `3e6d46f4563ab309aab2e7126ad3574ca18d02219746e59142ff6de6fc1c4eb3`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `c6b45d5c41f99f731f47585e48ce930e4b4c8af41e01cfbf576bb4396660d657`
- `command_inventory.json` SHA-256: `1c7147c4dc8e2e93074c7ae0d6424cf03e3a35643547a2d6c5f0ec10d093fd61`
- `mcp_capabilities.json` SHA-256: `27b2c8e985fea4a02946c6c5564f2a79d92fe8801427b45c30d3c45e71ae480c`
- Parsed HTML element IDs: 22
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 206; local links and cross-page fragments checked
- All 44 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 18

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
