#![feature(register_tool)]
#![register_tool(rr)]
#![feature(custom_inner_attributes)]

#![rr::package("formalkernel_refinedrust_array_regression")]

macro_rules! array_case {
    ($struct_name:ident, $standalone:ident, $embedded:ident, $length:expr) => {
        pub struct $struct_name {
            pub slots: [bool; $length],
        }

        #[rr::verify]
        pub fn $standalone(value: [bool; $length]) -> [bool; $length] {
            value
        }

        #[rr::verify]
        pub fn $embedded(value: $struct_name) -> $struct_name {
            value
        }
    };
}

array_case!(Slots0, standalone_0, embedded_0, 0);
array_case!(Slots1, standalone_1, embedded_1, 1);
array_case!(Slots2, standalone_2, embedded_2, 2);
array_case!(Slots4, standalone_4, embedded_4, 4);
array_case!(Slots16, standalone_16, embedded_16, 16);
