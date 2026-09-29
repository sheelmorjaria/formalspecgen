# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `ad3d6b1c4f08a03580a5d14857dd333c530eeff2d024b18c74606d7985186cd0`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `60aa8f79e5e6343adb844808ee2866c03794bc271f018343e3e47ff9721088f1`
- `command_inventory.json` SHA-256: `bb08a7bf5a7f4e40b420e49d86537fc8cbf7a85a534c3c9711a5e93f48d9ae18`
- `mcp_capabilities.json` SHA-256: `f2716e2b0ea431a6e7585957020ed3bd8633d95ef666b1f7faeb1dbabcabc136`
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
- Current landing-page CLI examples parsed against the real CLI: 17

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
