# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Shared deterministic formal-specification transformations.

This package is intentionally independent of either orchestration application so it can
be consumed by FormalSpecGen and, when installed or placed on PYTHONPATH, formalspecDD.
"""

from .postprocess import postprocess

__all__ = ["postprocess"]
