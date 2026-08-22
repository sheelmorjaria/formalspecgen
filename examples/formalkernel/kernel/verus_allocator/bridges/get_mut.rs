use vstd::prelude::*;

verus! {

fn clear_at<const N: usize>(slots: &mut [bool; N], index: usize) {
    if let Some(slot) = slots.get_mut(index) {
        *slot = false;
    }
}

} // verus!

fn main() {}
