# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Typed candidate schema for the M89 parameterized capability algebra."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class AuthorityOperation(BaseModel):
    name: Literal["mint_root", "derive", "delegate", "revoke", "check"]
    precondition: str
    effect: str
    refusal: Literal["stutter"]


class CapabilityAuthorityModel(BaseModel):
    schema_version: Literal[1] = 1
    lane: Literal["M89.1_reviewed_authority_algebra"]
    status: Literal["CAPABILITY_AUTHORITY_MODEL_CANDIDATE"]
    claim: Literal["NO_PROOF"]
    review_status: Literal["candidate"]
    parameterization: Literal["arbitrary_finite_principals_objects_rights"]
    capability_fields: list[str]
    operations: list[AuthorityOperation]
    invariants: list[str] = Field(min_length=5)
    proof_judge: Literal["TLAPS"]
    proof_executed: Literal[False]
    mutation_suite_executed: Literal[False]
    claims_locked: list[str]

    @model_validator(mode="after")
    def complete_algebra(self) -> "CapabilityAuthorityModel":
        if self.capability_fields != [
                "object", "rights", "owner", "generation", "validity"]:
            raise ValueError("capability state fields are incomplete")
        if [operation.name for operation in self.operations] != [
                "mint_root", "derive", "delegate", "revoke", "check"]:
            raise ValueError("authority transition surface is incomplete")
        return self
