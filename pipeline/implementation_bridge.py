# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Common evidence schema for production implementation/model bridge lanes."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class MutationClosure(BaseModel):
    executed: int = Field(ge=1)
    rejected: int = Field(ge=1)

    @model_validator(mode="after")
    def all_mutations_must_fail(self) -> "MutationClosure":
        if self.executed != self.rejected:
            raise ValueError("every required semantic mutation must be rejected")
        return self


class ImplementationBridgeEvidence(BaseModel):
    """Minimum common envelope; subsystem evidence may add narrower fields."""

    schema_version: Literal[1] = 1
    implementation_claim: str
    model_candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_review_status: Literal["candidate", "reviewed"]
    reviewed_model_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$")
    overlay_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verification_units: int = Field(ge=1)
    semantic_obligations: int = Field(ge=1)
    mutations: MutationClosure
    bridge_status: Literal["NO_PROOF", "HUMAN_REVIEW_PENDING", "PROVED"]
    trusted_assumptions: list[str]
    forbidden_claims: list[str]

    @model_validator(mode="after")
    def reviewed_hash_required_for_proof(self) -> "ImplementationBridgeEvidence":
        if self.bridge_status == "PROVED":
            if self.model_review_status != "reviewed" or not self.reviewed_model_sha256:
                raise ValueError("proved bridge requires a hash-bound reviewed model")
        return self
