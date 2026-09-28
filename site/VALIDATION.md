# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `8a477b11f1540cfcf42574ff14d1c94be9e38c4199cd8dc0c75a219e927ee38c`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `4084cf9c88229540d6897095eb46d199922df8945016cc72ff08b522f5bf3ffd`
- `command_inventory.json` SHA-256: `4bdddad23d904f07d2295619b12cb27f661380c04ce881ad8a172333685482fc`
- `mcp_capabilities.json` SHA-256: `14a1559ff40048408f5dd7e26e6fbb3955336e5d28cc1a893a4c6f5aa4d7e55d`
- Parsed HTML element IDs: 16
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 202; local links and cross-page fragments checked
- All 40 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 11

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
