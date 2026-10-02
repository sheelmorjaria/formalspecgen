# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `b989e2854dfb5b40a21d42c56909de58353fb829342e37d351599e4f2c4f38df`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `03ec982db2f9697e1267870c8a616405036ec383eb66662cd4c9cc8ba2479ba9`
- `command_inventory.json` SHA-256: `3c7ab21e9e7b418efba2c3def36c6ac4475fd804edc32da812a0b7c16eb7ff59`
- `mcp_capabilities.json` SHA-256: `877f731deb2c0545467d74a4150c63b82b7518ce3c6248467e24d961cd06f01f`
- Parsed HTML element IDs: 24
- Same-page fragment links checked: 18
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
