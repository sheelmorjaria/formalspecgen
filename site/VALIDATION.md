# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `61f8adc184056a1fc660ae3ba69c297fd963ef31b573f35a71ed58711a74d9cc`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `64f2b77db7f1b94b425385f4ea8f1bde922ce51289958c7278fa73a622ed7fa6`
- `command_inventory.json` SHA-256: `0758ac3ab3a9eff8f723f5ef20e1321bc8b0868af16e96ce5c9947ec0f7f4c8f`
- `mcp_capabilities.json` SHA-256: `fa802fde13e9b4835e7c52076271aa3bd2d4e2484c6086016f4db900957fafdf`
- Parsed HTML element IDs: 17
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 203; local links and cross-page fragments checked
- All 41 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 12

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
