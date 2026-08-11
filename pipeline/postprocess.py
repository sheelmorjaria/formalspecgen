# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Compatibility facade for the shared deterministic postprocessor library."""

from formalspec_core.postprocess import (  # noqa: F401
    fix_inner_loop_spec_placement,
    guard_array_access,
    guard_exclusion_invariants,
    inject_bidirectional_old,
    inject_bitshift_bounds,
    inject_nonlinear_index_assume,
    inject_overflow_bounds,
    inject_pure,
    inject_sum_helper,
    inject_sum_invariant,
    postprocess,
    strengthen_sorted,
    strip_exit_invariants,
    strip_result_from_invariants,
)

__all__ = [
    "postprocess",
    "strip_exit_invariants",
    "strip_result_from_invariants",
    "fix_inner_loop_spec_placement",
    "inject_overflow_bounds",
    "inject_bitshift_bounds",
    "inject_sum_invariant",
    "inject_sum_helper",
    "inject_bidirectional_old",
    "guard_array_access",
    "guard_exclusion_invariants",
    "strengthen_sorted",
    "inject_pure",
    "inject_nonlinear_index_assume",
]
