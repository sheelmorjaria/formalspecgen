#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! -x .venv-e2e/bin/python ]]; then
  python3 -m venv .venv-e2e
fi
.venv-e2e/bin/python -m pip install -r requirements-e2e.txt

live_args=()
if [[ "${RUN_LIVE_LLM_E2E:-0}" == "1" ]]; then
  live_args+=(--live-llm)
else
  live_args+=(-m "not live_llm")
fi

.venv-e2e/bin/pytest -c tests_e2e/pytest.ini "${live_args[@]}" tests_e2e

if [[ "${RUN_VSCODE_E2E:-0}" == "1" ]]; then
  npm --prefix vscode-extension ci
  npm --prefix vscode-extension run test:e2e
fi
