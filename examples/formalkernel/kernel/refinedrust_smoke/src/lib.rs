#![feature(register_tool)]
#![register_tool(rr)]
#![feature(custom_inner_attributes)]

#![rr::package("formalkernel_refinedrust_smoke")]

/// The smallest source-level relational theorem used to qualify the
/// foundational lane before it is applied to a kernel state machine.
#[rr::params("value")]
#[rr::args("value")]
#[rr::returns("value")]
pub fn preserve(value: i32) -> i32 {
    value
}
