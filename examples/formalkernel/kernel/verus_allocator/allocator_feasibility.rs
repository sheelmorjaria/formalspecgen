use vstd::prelude::*;

// Include the production module directly so Verus judges the exact bytes. The
// harness contains no proof-specific copy or semantically rewritten allocator.
#[path = "../user/heap.rs"]
mod production_heap;

fn main() {}
