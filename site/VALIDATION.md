# Published guide validation

This record describes preparation of the current static GitHub Pages edition. It is
documentation validation, not formal verification or revision-bound acceptance evidence.

## Checked publication inputs

- `index.html` SHA-256: `d18a1984f03160e82b5326a7b20450861fed1d5c74f601ae03a692d3bc150961`
- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `4a7b32cc4f15eba1086a8856a2f6ff3620f48756167ef7a14469c113b87af96a`
- `command_inventory.json` SHA-256: `c6438309b6768fdde04626c442debfffbdef7d8bf910067559cdddf8ccce5d56`
- `mcp_capabilities.json` SHA-256: `bf9353dc29b2d5893f5d6683ab6009dc2533c7931e14a850b209f949e681bb85`
- Parsed HTML element IDs: 15
- Same-page fragment links checked: 18
- Missing same-page targets: none
- Duplicate element IDs: none
- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,
  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide
- Operating-manual IDs: 201; local links and cross-page fragments checked
- All 39 command-reference and index admission labels generated from the live inventory
- Unexpected relative assets: none
- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models
- Current landing-page CLI examples parsed against the real CLI: 10

## Scope limits

- External URLs were retained but not fetched as part of publication validation.
- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.
- No compiler, verifier, generated program, provider, or MCP transport was run.
- Static handler schemas do not replace runtime MCP discovery acceptance.
- Completion claims must be checked against the linked revision-bound CI evidence.
