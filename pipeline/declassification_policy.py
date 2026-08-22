# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Reviewed, precise declassification policy schema for M88.4."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class DeclassificationRule(BaseModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    high_source: str
    low_sink: str
    enabling_condition: str
    released_projection: str


class DeclassificationPolicy(BaseModel):
    schema_version: Literal[1] = 1
    lane: str
    status: Literal["DECLASSIFICATION_POLICY_CANDIDATE"]
    claim: Literal["NO_PROOF"]
    review_status: Literal["candidate"]
    rules: list[DeclassificationRule] = Field(min_length=1)
    information_flow_scope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trace_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trace_depth: int = Field(ge=2)
    termination_sensitive: Literal[False]
    timing_sensitive: Literal[False]
    proof_families_executed: list[str]
    policy_mutations_rejected: int = Field(ge=0)
    claims_locked: list[str]

    @model_validator(mode="after")
    def rules_must_be_isolated(self) -> "DeclassificationPolicy":
        identifiers = [rule.id for rule in self.rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("declassification rule IDs must be unique")
        for rule in self.rules:
            if rule.high_source == rule.low_sink:
                raise ValueError("declassification must cross an explicit boundary")
        return self
