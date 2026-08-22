#![feature(register_tool)]
#![register_tool(rr)]
#![feature(custom_inner_attributes)]
#![rr::package("formalkernel_refinedrust_allocator")]
// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0
//! Allocation-free EL0 heap ledger backed by kernel-assigned frames.

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
    /// Construct an empty heap ledger.
    #[rr::verify]
    pub const fn new() -> Self {
        Self {
            occupied: [false; HEAP_BLOCKS],
        }
    }

    /// Allocate one fixed-size block or return bounded backpressure.
    #[rr::verify]
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
    #[rr::verify]
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
    #[rr::verify]
    pub fn allocated(&self) -> usize {
        self.occupied.iter().filter(|slot| **slot).count()
    }
}

impl Default for UserHeap {
    fn default() -> Self {
        Self::new()
    }
}
