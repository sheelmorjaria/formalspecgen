// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0
//! Allocation-free EL0 heap ledger backed by kernel-assigned frames.

/* VERUS_OVERLAY_BEGIN:crate */
use vstd::prelude::*;

verus! {
/* VERUS_OVERLAY_END:crate */
/// Number of fixed-size blocks in one process heap grant.
pub const HEAP_BLOCKS: usize = 16;
/// Bytes represented by each ledger slot.
pub const BLOCK_BYTES: usize = 256;
/// Total physical footprint required from the process heap pool.
pub const HEAP_BYTES: usize = HEAP_BLOCKS * BLOCK_BYTES;

/// Opaque block handle; callers never receive a kernel physical address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockId(usize);

/// Deterministic allocation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapError {
    /// Every kernel-granted block is occupied.
    Exhausted,
    /// The handle is outside the grant or has already been released.
    InvalidBlock,
}

/// Fixed-capacity user heap with no dynamic metadata allocation.
pub struct UserHeap {
    occupied: [bool; HEAP_BLOCKS],
}

impl UserHeap {
    /* VERUS_OVERLAY_BEGIN:view */
    pub closed spec fn occupied_view(&self) -> Seq<bool> {
        self.occupied@
    }
    /* VERUS_OVERLAY_END:view */
    /// Construct an empty heap ledger.
    /* VERUS_OVERLAY_REPLACE:pub const fn new() -> Self { */
    pub const fn new() -> (result: Self)
        ensures
            result.occupied_view() == Seq::new(HEAP_BLOCKS as nat, |i: int| false),
    {
    /* VERUS_OVERLAY_REPLACE_END */
        Self {
            occupied: [false; HEAP_BLOCKS],
        }
    }

    /// Allocate one fixed-size block or return bounded backpressure.
    /* VERUS_OVERLAY_BEGIN:exclude_allocate */
    #[verifier::external]
    /* VERUS_OVERLAY_END:exclude_allocate */
    pub fn allocate(&mut self) -> Result<BlockId, HeapError> {
        for (index, occupied) in self.occupied.iter_mut().enumerate() {
            if !*occupied {
                *occupied = true;
                return Ok(BlockId(index));
            }
        }
        Err(HeapError::Exhausted)
    }

    /// Release one live block exactly once.
    /* VERUS_OVERLAY_BEGIN:exclude_release */
    #[verifier::external]
    /* VERUS_OVERLAY_END:exclude_release */
    pub fn release(&mut self, block: BlockId) -> Result<(), HeapError> {
        let occupied = self
            .occupied
            .get_mut(block.0)
            .ok_or(HeapError::InvalidBlock)?;
        if !*occupied {
            return Err(HeapError::InvalidBlock);
        }
        *occupied = false;
        Ok(())
    }

    /// Return the number of occupied blocks.
    /* VERUS_OVERLAY_BEGIN:exclude_allocated */
    #[verifier::external]
    /* VERUS_OVERLAY_END:exclude_allocated */
    pub fn allocated(&self) -> usize {
        self.occupied.iter().filter(|slot| **slot).count()
    }
}

/* VERUS_OVERLAY_BEGIN:exclude_default */
#[verifier::external]
/* VERUS_OVERLAY_END:exclude_default */
impl Default for UserHeap {
    fn default() -> Self {
        Self::new()
    }
}
/* VERUS_OVERLAY_BEGIN:crate_end */
} // verus!

fn main() {}
/* VERUS_OVERLAY_END:crate_end */
