# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""FormalSpecGen pipeline — natural language to contracts and verified implementations.

The active native flow drafts JML from natural language, validates it with
``openjml -check``, synthesizes Java bodies, and verifies them with ``openjml -esc``.

Infrastructure (config/llm/verify/parse_vcs/strategy/schemas) is ported from
formalspecDD; see SHARED_LINEAGE.md.
"""
