# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed registry and selection for semantic domain plugins."""
from dataclasses import dataclass
from typing import Any, Callable


class UnsupportedDomain(ValueError):
    pass


class AmbiguousDomain(ValueError):
    pass


@dataclass(frozen=True)
class DomainPlugin:
    name: str
    recognizes: Callable[[str], bool]
    extract: Callable[[str, str, str | None], tuple[Any, list[dict]]]
    render: Callable[[Any], tuple[str, str]]


def select_domain(code: str, plugins: list[DomainPlugin]) -> DomainPlugin:
    matches = [plugin for plugin in plugins if plugin.recognizes(code)]
    if not matches:
        raise UnsupportedDomain("No reviewed domain plugin recognizes this complete API")
    if len(matches) > 1:
        raise AmbiguousDomain("Multiple domain plugins matched: " +
                              ", ".join(plugin.name for plugin in matches))
    return matches[0]
