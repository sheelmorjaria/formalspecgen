# Archived generated artifacts

This directory contains outputs produced by local experiments and test-input runs. They are kept
for traceability but are not part of the executable FormalSpecGen pipeline.

- `test-runs/` contains refactoring candidates, inspections, verdicts, and failed design-system
  provider evidence.
- `root-implementations/` contains generated Java implementations that were previously left in
  the repository root but are not tracked source fixtures.
- Do not use these files as trusted domains or production implementation inputs without rerunning
  the relevant validation and promotion gates.
