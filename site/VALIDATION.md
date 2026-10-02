# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `ae3d8dbdfce5f03afbe74455dc6834be0eec1f312d139c5d85baa272a37a7879`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `d85fd6a0d122acc17062d81d69954b3a1cece52041934ebcfbd268ed531f21a1`
- `command_inventory.json` SHA-256: `f7c5c4f10692c1830d7ec1d65e147667b0b1356263c475b7a4f87e0f009f1883`
- `mcp_capabilities.json` SHA-256: `52d03f860ec38ac44572e1efee43eb298c4e3c36efcc86dc3d1fd86c1a203bcc`
- Parsed HTML element IDs: 23
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 206; local links and cross-page fragments checked
- All 44 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 19

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
