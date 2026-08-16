# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Registry of pattern-detection plugins driving deterministic inspection.

Each entry binds a detector class from :mod:`pipeline.java_inspection` to its
catalog metadata (pattern name, GoF-style category, target languages, and the
optional ``apply-refactor`` profile its finding can drive). Inspection iterates
this registry, so adding a pattern means adding one plugin here.
"""
from __future__ import annotations

from dataclasses import dataclass

from .java_inspection import (
    AdapterDetector,
    BuilderOpportunityDetector,
    CommandDetector,
    CoreStructureDetector,
    DecoratorDetector,
    FactoryMethodDetector,
    NullObjectDetector,
    ObserverDetector,
    ProducerConsumerDetector,
    ProxyDetector,
    RepositoryDetector,
    SingletonDetector,
    StatePatternDetector,
)


@dataclass(frozen=True)
class PatternPlugin:
    """One registered pattern detector plus its catalog metadata."""
    name: str                     # e.g. "Null Object"
    category: str                 # "Creational" | "Structural" | "Behavioral" | "Concurrency"
    detector: type                # a PatternDetector subclass from pipeline.java_inspection
    languages: tuple[str, ...] = ("java",)
    action_profile: str | None = None  # apply-refactor slug or None (inspection-only)


PATTERN_REGISTRY: list[PatternPlugin] = [
    PatternPlugin("Core Structure", "Structural", CoreStructureDetector),
    PatternPlugin("Singleton", "Creational", SingletonDetector),
    PatternPlugin("Observer", "Behavioral", ObserverDetector),
    PatternPlugin("Builder", "Creational", BuilderOpportunityDetector),
    PatternPlugin("Repository", "Structural", RepositoryDetector),
    PatternPlugin("Adapter", "Structural", AdapterDetector),
    PatternPlugin("Factory Method", "Creational", FactoryMethodDetector,
                  action_profile="factory-method"),
    PatternPlugin("State", "Behavioral", StatePatternDetector, action_profile="state"),
    PatternPlugin("Decorator", "Structural", DecoratorDetector, action_profile="decorator"),
    PatternPlugin("Null Object", "Structural", NullObjectDetector,
                  action_profile="null-object"),
    PatternPlugin("Proxy", "Structural", ProxyDetector),
    PatternPlugin("Command", "Behavioral", CommandDetector),
    PatternPlugin("Producer-Consumer", "Concurrency", ProducerConsumerDetector),
]

# Compatibility re-export: detector classes in registry order.
DETECTOR_REGISTRY = tuple(plugin.detector for plugin in PATTERN_REGISTRY)
