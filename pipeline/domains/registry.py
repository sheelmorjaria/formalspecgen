# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic plugin registry; updated by scaffold_domain, included by PyInstaller."""
from .banking import BANKING_PLUGIN
from .inventory_render import INVENTORY_PLUGIN
from .train_crossing_render import TRAIN_CROSSING_PLUGIN
# BEGIN SCAFFOLDED IMPORTS
from .traffic_light_controller_render import TRAFFIC_LIGHT_CONTROLLER_PLUGIN
from .elevator_controller_render import ELEVATOR_CONTROLLER_PLUGIN
from .smart_lock_render import SMART_LOCK_PLUGIN
from .robot_vacuum_controller_render import ROBOT_VACUUM_CONTROLLER_PLUGIN
# END SCAFFOLDED IMPORTS

PLUGINS = [
    BANKING_PLUGIN,
    INVENTORY_PLUGIN,
    TRAIN_CROSSING_PLUGIN,
    # BEGIN SCAFFOLDED PLUGINS
    TRAFFIC_LIGHT_CONTROLLER_PLUGIN,
    ELEVATOR_CONTROLLER_PLUGIN,
    SMART_LOCK_PLUGIN,
    ROBOT_VACUUM_CONTROLLER_PLUGIN,
    # END SCAFFOLDED PLUGINS
]
