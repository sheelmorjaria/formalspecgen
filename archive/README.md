# Archived interfaces

This directory preserves the former VS Code, browser, and FastAPI interfaces for historical
reference and possible future extraction into separate client packages.

- `vscode-extension/`: VS Code webviews, language server, bootstrap runtime, and VSIX packaging.
- `static/`: browser interface.
- `server.py`: REST/WebSocket adapter over the Python pipeline.
- `server-tests/`: server API and protocol tests.
- `e2e/`: archived WebSocket end-to-end test.
- `packaging/`: former PyInstaller server specification.
- `formalspecdd-compat/`: retired sibling-repository handoff, fixtures, and tests.
- `research-results/eval-reports/`: historical evaluation reports; the evaluation code remains active.
- `README-VSCODE-AND-SERVER.md`: full documentation for the archived product architecture.

Generated extension dependencies and build products are deliberately not retained. Archived code
is not imported, packaged, tested, or required by the active terminal CLI. Security
or dependency fixes applied to the CLI do not imply maintenance of these archived clients.
