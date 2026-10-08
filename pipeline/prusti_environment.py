# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Keep FormalSpecGen metadata out of Prusti's configuration namespace."""
import os

_PRUSTI_INTERNAL_ENV_KEYS = frozenset({
    "PRUSTI_BIN", "PRUSTI_VERSION", "PRUSTI_SHA256",
})


def prusti_subprocess_env() -> dict[str, str]:
    """Copy the host environment, preserving legitimate Prusti configuration."""
    env = os.environ.copy()
    for key in _PRUSTI_INTERNAL_ENV_KEYS:
        env.pop(key, None)
    return env
