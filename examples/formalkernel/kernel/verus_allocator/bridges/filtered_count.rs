use vstd::prelude::*;

verus! {

fn occupied_count<const N: usize>(slots: &[bool; N]) -> usize {
    slots.iter().filter(|slot| **slot).count()
}

} // verus!

fn main() {}
