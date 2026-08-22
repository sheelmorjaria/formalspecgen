use vstd::prelude::*;

verus! {

fn traverse_mut<const N: usize>(slots: &mut [bool; N]) {
    for (_index, slot) in slots.iter_mut().enumerate() {
        if !*slot {
            *slot = true;
            return;
        }
    }
}

} // verus!

fn main() {}
