# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Banking plugin facade over the existing reviewed semantic adapter."""
from ..extract_tla_ir import extract_banking_model
from ..tla_backend import detect_banking_boundary
from ..tla_ir import render_banking_model
from .router import DomainPlugin


BANKING_PLUGIN = DomainPlugin(
    name="bank_account",
    recognizes=detect_banking_boundary,
    extract=extract_banking_model,
    render=render_banking_model,
)
