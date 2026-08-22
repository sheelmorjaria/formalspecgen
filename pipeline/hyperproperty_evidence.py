# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Scoped evidence schema for relational information-flow properties."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class HyperpropertyScope(BaseModel):
    security_property_class: Literal["two_run_noninterference"]
    high_state_fields: list[str] = Field(min_length=1)
    public_inputs: list[str] = Field(min_length=1)
    low_observables: list[str] = Field(min_length=1)
    declassification_rules: list[str]
    termination_sensitive: bool
    timing_sensitive: bool

    @model_validator(mode="after")
    def partitions_must_be_explicit(self) -> "HyperpropertyScope":
        overlap = set(self.high_state_fields) & set(self.low_observables)
        if overlap:
            raise ValueError(f"high fields cannot be low observables: {sorted(overlap)}")
        return self


class HyperpropertyEvidence(BaseModel):
    schema_version: Literal[1] = 1
    lane: str
    status: str
    claim: str
    scope_review_status: Literal["candidate", "reviewed"]
    reviewed_scope_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$")
    scope: HyperpropertyScope
    artifact_sha256: dict[str, str]
    two_run_judgment_executed: bool
    confidentiality_mutation_rejected: bool
    trusted_assumptions: list[str]
    forbidden_claims: list[str]

    @model_validator(mode="after")
    def proof_requires_judgment_and_mutation(self) -> "HyperpropertyEvidence":
        if self.claim != "NO_PROOF" and not (
                self.two_run_judgment_executed and self.confidentiality_mutation_rejected):
            raise ValueError("noninterference claim requires judge and mutation closure")
        if self.claim != "NO_PROOF" and (
                self.scope_review_status != "reviewed" or not self.reviewed_scope_sha256):
            raise ValueError("noninterference claim requires a reviewed scope hash")
        return self
