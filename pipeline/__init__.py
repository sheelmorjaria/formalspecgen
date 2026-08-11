# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""formalspecgen pipeline — natural-language (NL) -> validated JML specification.

The dual of formalspecDD: DD fills Java method bodies from trusted JML specs and
verifies them with `openjml -esc`; this project drafts the JML specs from natural
language and validates them with `openjml -check`. The two compose:
    NL -> [formalspecgen] -> JML stub -> [formalspecDD] -> verified Java.

Infrastructure (config/llm/verify/parse_vcs/strategy/schemas) is ported from
formalspecDD; see SHARED_LINEAGE.md.
"""
