// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0
use vstd::prelude::*;

verus! {

fn preserve(value: u32) -> (result: u32)
    ensures
        result == value,
{
    value
}

} // verus!

fn main() {}
