# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic plugin registry; updated by scaffold_domain, included by PyInstaller."""
from .banking import BANKING_PLUGIN
from .inventory_render import INVENTORY_PLUGIN
from .train_crossing_render import TRAIN_CROSSING_PLUGIN
# BEGIN SCAFFOLDED IMPORTS
# END SCAFFOLDED IMPORTS

PLUGINS = [
    BANKING_PLUGIN,
    INVENTORY_PLUGIN,
    TRAIN_CROSSING_PLUGIN,
    # BEGIN SCAFFOLDED PLUGINS
    # END SCAFFOLDED PLUGINS
]
