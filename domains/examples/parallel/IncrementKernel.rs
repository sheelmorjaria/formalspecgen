use prusti_contracts::*;

/// Adds one within the reviewed non-overflowing input range.
#[requires(value < 2147483647)]
#[ensures(result == value + 1)]
pub fn process_chunk(value: i32) -> i32 {
    value + 1
}
