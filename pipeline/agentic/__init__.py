# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Supervised, permission-bound goal execution.

The first agentic profile is deliberately narrow: it may inspect one approved
source snapshot and request one admitted verification.  It cannot edit source,
change a contract, select arbitrary tools, call providers, delegate work, sign,
promote, or merge.
"""

from .contracts import AgentGoal, AgentRunError
from .supervisor import AgentSupervisor

__all__ = ["AgentGoal", "AgentRunError", "AgentSupervisor"]
