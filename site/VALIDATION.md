# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `f7d6bfe1123923c6f4f0178e3aa0db97f6811b0cdeafa1cf044b6731300a5d90`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `5d03e18e91ac09de0ecac98837138c9b48a27b15067df3f8c2bb23bfb1c26302`
- `command_inventory.json` SHA-256: `a50fcd5f3f0305211b7fc4b792d50b1bf768d5cce525cd0c88865526051ffe2b`
- `mcp_capabilities.json` SHA-256: `e737e2b66956570a2d28231d73eee9f0a4518008ad63d0f352ad17ceed21181d`
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
