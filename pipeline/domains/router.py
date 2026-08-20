# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed registry and selection for semantic domain plugins."""
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class UnsupportedDomain(ValueError):
    pass


class AmbiguousDomain(ValueError):
    pass


class DomainMaturity(str, Enum):
    SCAFFOLD = "scaffold"
    BOUNDED_EVIDENCE = "bounded-evidence"
    PRODUCTION = "production"


_MATURITY_RANK = {
    DomainMaturity.SCAFFOLD: 0,
    DomainMaturity.BOUNDED_EVIDENCE: 1,
    DomainMaturity.PRODUCTION: 2,
}


@dataclass(frozen=True)
class DomainPlugin:
    name: str
    recognizes: Callable[[str], bool]
    extract: Callable[[str, str, str | None], tuple[Any, list[dict]]]
    render: Callable[[Any], tuple[str, str]]
    maturity: DomainMaturity = DomainMaturity.SCAFFOLD
    evidence_ceiling: str = "NO_PROOF"
    maturity_note: str = "Generated adapter; semantic mapping is not reviewed."


def select_domain(code: str, plugins: list[DomainPlugin], *,
                  minimum_maturity: DomainMaturity = DomainMaturity.SCAFFOLD) -> DomainPlugin:
    matches = [plugin for plugin in plugins if plugin.recognizes(code)]
    if not matches:
        raise UnsupportedDomain("No reviewed domain plugin recognizes this complete API")
    if len(matches) > 1:
        raise AmbiguousDomain("Multiple domain plugins matched: " +
                              ", ".join(plugin.name for plugin in matches))
    selected = matches[0]
    if _MATURITY_RANK[selected.maturity] < _MATURITY_RANK[minimum_maturity]:
        raise UnsupportedDomain(
            f"Domain {selected.name!r} is maturity {selected.maturity.value!r}; "
            f"this operation requires {minimum_maturity.value!r}. "
            f"Evidence ceiling: {selected.evidence_ceiling}. {selected.maturity_note}")
    return selected


def maturity_report(plugins: list[DomainPlugin]) -> list[dict[str, Any]]:
    operations = {
        DomainMaturity.SCAFFOLD: ["recognize"],
        DomainMaturity.BOUNDED_EVIDENCE: ["recognize", "bounded_architecture"],
        DomainMaturity.PRODUCTION: ["recognize", "bounded_architecture",
                                    "critical_implementation"],
    }
    return [{"name": plugin.name, "maturity": plugin.maturity.value,
             "evidence_ceiling": plugin.evidence_ceiling,
             "available_operations": operations[plugin.maturity],
             "critical_implementation_available":
                 plugin.maturity is DomainMaturity.PRODUCTION,
             "note": plugin.maturity_note}
            for plugin in sorted(plugins, key=lambda item: item.name)]
