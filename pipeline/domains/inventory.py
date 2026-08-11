# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Strict bounded IR for the reviewed inventory domain."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..transition_ir import MethodTransitionIR


InventoryOperation = Literal["addStock", "reserve", "release"]
InventoryGuard = Literal[
    "positive_amount", "stock_has_capacity", "enough_available_stock",
    "enough_reserved_stock",
]
InventoryEffect = Literal["increase_stock", "reserve_stock", "release_stock"]
InventoryFrame = Literal["product_stock", "product_reserved"]


class InventoryOperationIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: InventoryOperation
    guard_ids: list[InventoryGuard]
    effect_id: InventoryEffect
    frame_ids: list[InventoryFrame]
    result_constrained: bool
    failure_preserves_frame: bool


class InventoryTlaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    domain: Literal["inventory"] = "inventory"
    products: int = Field(default=2, ge=1, le=4)
    actors: int = Field(default=2, ge=1, le=4)
    max_stock: int = Field(default=4, ge=1, le=20)
    amounts: list[int] = Field(default_factory=lambda: [1, 2], min_length=1, max_length=5)
    operations: list[InventoryOperationIR]
    transitions: list[MethodTransitionIR]

    @model_validator(mode="after")
    def validate_model(self) -> "InventoryTlaModel":
        expected = ["addStock", "reserve", "release"]
        if [item.operation for item in self.operations] != expected:
            raise ValueError("inventory operations must be addStock, reserve, release")
        if [item.name for item in self.transitions] != expected:
            raise ValueError("inventory transitions must correspond to operations")
        if len(set(self.amounts)) != len(self.amounts) or any(
                value <= 0 or value > self.max_stock for value in self.amounts):
            raise ValueError("amounts must be unique, positive, and bounded by max_stock")
        return self
