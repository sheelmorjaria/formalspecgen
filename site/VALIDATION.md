# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `76774ae04b707e58c9f2aa3e53c937f67aeb7a60b78df93e2e75594f331db7ea`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `a243df33784a993a0f3cd70a92db521d7922b3ba0d1967eeda057dc72190cd30`
- `command_inventory.json` SHA-256: `956059f3b161da2259a5b69dd5812baf8b931eac8ce541a4483f99d75abae324`
- `mcp_capabilities.json` SHA-256: `9ec99fa8c41fba8c41a5d913eff2cf443d28795cdcb49875ea1da6ac4b2f9eb6`
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
