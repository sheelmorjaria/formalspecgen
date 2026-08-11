# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic reviewed TLA+ renderer for bounded inventory contracts."""
from .inventory import InventoryTlaModel


def render_inventory(model: InventoryTlaModel) -> tuple[str, str]:
    products = ", ".join(str(index) for index in range(1, model.products + 1))
    actors = ", ".join(str(index) for index in range(1, model.actors + 1))
    amounts = ", ".join(str(value) for value in model.amounts)
    effects = {item.effect_id for item in model.operations}
    if effects != {"increase_stock", "reserve_stock", "release_stock"}:
        raise ValueError("UNSUPPORTED_BOUNDARY: inventory effect set is incomplete")
    tla = f"""---- MODULE BoundedInventory ----
EXTENDS Naturals

Products == {{{products}}}
Actors == {{{actors}}}
Amounts == {{{amounts}}}
MaxStock == {model.max_stock}

VARIABLES stock, reserved
vars == <<stock, reserved>>

Init ==
    /\\ stock = [product \\in Products |-> 0]
    /\\ reserved = [product \\in Products |-> 0]

AddStock(product, amount) ==
    /\\ product \\in Products
    /\\ amount \\in Amounts
    /\\ stock[product] + amount <= MaxStock
    /\\ stock' = [stock EXCEPT ![product] = @ + amount]
    /\\ UNCHANGED reserved

Reserve(product, amount) ==
    /\\ product \\in Products
    /\\ amount \\in Amounts
    /\\ reserved[product] + amount <= stock[product]
    /\\ reserved' = [reserved EXCEPT ![product] = @ + amount]
    /\\ UNCHANGED stock

Release(product, amount) ==
    /\\ product \\in Products
    /\\ amount \\in Amounts
    /\\ amount <= reserved[product]
    /\\ reserved' = [reserved EXCEPT ![product] = @ - amount]
    /\\ UNCHANGED stock

Next ==
    \\/ \\E product \\in Products, amount \\in Amounts : AddStock(product, amount)
    \\/ \\E product \\in Products, amount \\in Amounts : Reserve(product, amount)
    \\/ \\E product \\in Products, amount \\in Amounts : Release(product, amount)

TypeOK ==
    /\\ stock \\in [Products -> 0..MaxStock]
    /\\ reserved \\in [Products -> 0..MaxStock]
StockNonNegative == \\A product \\in Products : stock[product] >= 0
ReservedNonNegative == \\A product \\in Products : reserved[product] >= 0
ReservedWithinStock == \\A product \\in Products : reserved[product] <= stock[product]

Spec == Init /\\ [][Next]_vars
===="""
    cfg = """SPECIFICATION Spec
INVARIANT TypeOK
INVARIANT StockNonNegative
INVARIANT ReservedNonNegative
INVARIANT ReservedWithinStock
CHECK_DEADLOCK FALSE"""
    return tla, cfg


from .inventory_extract import recognizes_inventory, extract_inventory_model
from .router import DomainPlugin

INVENTORY_PLUGIN = DomainPlugin("inventory", recognizes_inventory,
                                extract_inventory_model, render_inventory)
